import uuid
import requests
from datetime import timedelta
from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponse
from django.shortcuts import redirect
from django.utils import timezone
from intuitlib.client import AuthClient
from intuitlib.enums import Scopes


def connect_to_quickbooks(request):
    """
    Redirect user to QuickBooks OAuth authorization page.
    """
    state = str(uuid.uuid4())
    request.session['qb_oauth_state'] = state

    auth_client = AuthClient(
        client_id=settings.QBO_CLIENT_ID,
        client_secret=settings.QBO_CLIENT_SECRET,
        redirect_uri=settings.QBO_REDIRECT_URI,
        environment=settings.QBO_ENVIRONMENT,
    )

    # Use Accounting scope
    authorization_url = auth_client.get_authorization_url([Scopes.ACCOUNTING, Scopes.OPENID], state_token=state)
    return redirect(authorization_url)


def quickbooks_callback(request):
    """
    Handle OAuth callback, exchange code for access/refresh tokens,
    and store them in session.
    """
    code = request.GET.get('code')
    state = request.GET.get('state')
    realm_id = request.GET.get('realmId')

    saved_state = request.session.get('qb_oauth_state')
    if not state or state != saved_state:
        return HttpResponseBadRequest("Invalid state parameter")

    auth_client = AuthClient(
        client_id=settings.QBO_CLIENT_ID,
        client_secret=settings.QBO_CLIENT_SECRET,
        redirect_uri=settings.QBO_REDIRECT_URI,
        environment=settings.QBO_ENVIRONMENT,
    )

    try:
        auth_client.get_bearer_token(code, realm_id=realm_id)
    except Exception as e:
        return HttpResponse(f"Error obtaining token: {e}", status=500)

    # Store tokens and realm_id in session
    request.session['qb_access_token'] = auth_client.access_token
    request.session['qb_refresh_token'] = auth_client.refresh_token
    request.session['qb_realm_id'] = realm_id
    request.session['qb_token_expiry'] = (timezone.now() + timedelta(seconds=auth_client.expires_in)).timestamp()

    return HttpResponse("QuickBooks connected successfully!")


def refresh_qb_token(request):
    """
    Refresh access token if expired, using session-stored refresh token.
    """
    access_token = request.session.get('qb_access_token')
    refresh_token = request.session.get('qb_refresh_token')
    token_expiry = request.session.get('qb_token_expiry')

    if not access_token or not refresh_token:
        return None

    # Convert token_expiry to timezone-aware datetime
    expiry_time = timezone.datetime.fromtimestamp(token_expiry, tz=timezone.get_current_timezone())

    # If token is still valid for 5+ minutes, return it
    if expiry_time > timezone.now() + timedelta(minutes=5):
        return access_token

    # Token expired → refresh
    try:
        auth_client = AuthClient(
            client_id=settings.QBO_CLIENT_ID,
            client_secret=settings.QBO_CLIENT_SECRET,
            redirect_uri=settings.QBO_REDIRECT_URI,
            environment=settings.QBO_ENVIRONMENT,
        )
        auth_client.refresh(refresh_token)

        # Update session
        request.session['qb_access_token'] = auth_client.access_token
        request.session['qb_refresh_token'] = auth_client.refresh_token
        request.session['qb_token_expiry'] = (timezone.now() + timedelta(seconds=auth_client.expires_in)).timestamp()

        return auth_client.access_token
    except Exception as e:
        print("QuickBooks token refresh failed:", str(e))
        return None


def get_customers(request):
    """
    Fetch QuickBooks customers using session-stored tokens.
    """
    access_token = refresh_qb_token(request)
    realm_id = request.session.get('qb_realm_id')

    if not access_token or not realm_id:
        return JsonResponse({"error": "QuickBooks not connected or token expired"}, status=400)

    base_url = settings.QBO_BASE_URL
    url = f"{base_url}/v3/company/{realm_id}/query"
    query = "SELECT * FROM Customer MAXRESULTS 31"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, params={"query": query}, timeout=10)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.HTTPError as e:
        if response.status_code == 401:
            data = {"error": "Unauthorized: Access token may have expired"}
        else:
            data = {"error": "QuickBooks API HTTP error", "details": str(e)}
    except requests.exceptions.RequestException as e:
        data = {"error": "QuickBooks API request failed", "details": str(e)}

    return JsonResponse(data)


def get_company_info(request):
    """
    Fetch QuickBooks company info using session-stored tokens.
    """
    access_token = refresh_qb_token(request)
    realm_id = request.session.get('qb_realm_id')

    if not access_token or not realm_id:
        return JsonResponse({"error": "QuickBooks not connected"}, status=400)

    base_url = settings.QBO_BASE_URL
    url = f"{base_url}/v3/company/{realm_id}/companyinfo/{realm_id}"

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        data = {"error": "QuickBooks API request failed", "details": str(e)}

    return JsonResponse(data)


def get_customer(request, id):
    """
    Fetch QuickBooks customers using session-stored tokens.
    """
    access_token = refresh_qb_token(request)
    realm_id = request.session.get('qb_realm_id')

    if not access_token or not realm_id:
        return JsonResponse({"error": "QuickBooks not connected or token expired"}, status=400)

    base_url = settings.QBO_BASE_URL
    url = f"{base_url}/v3/company/{realm_id}/customer/{id}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.HTTPError as e:
        if response.status_code == 401:
            data = {"error": "Unauthorized: Access token may have expired"}
        else:
            data = {"error": "QuickBooks API HTTP error", "details": str(e)}
    except requests.exceptions.RequestException as e:
        data = {"error": "QuickBooks API request failed", "details": str(e)}

    return JsonResponse(data)


def get_invoices(request):
    """
    Fetch QuickBooks customers using session-stored tokens.
    """
    access_token = refresh_qb_token(request)
    realm_id = request.session.get('qb_realm_id')

    if not access_token or not realm_id:
        return JsonResponse({"error": "QuickBooks not connected or token expired"}, status=400)

    base_url = settings.QBO_BASE_URL
    url = f"{base_url}/v3/company/{realm_id}/query"
    params = {
        "query": "SELECT * FROM Invoice  MAXRESULTS 5",
        "minorversion": "75"  #
    }
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        print(response.url)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.HTTPError as e:
        if response.status_code == 401:
            data = {"error": "Unauthorized: Access token may have expired"}
        else:
            data = {"error": "QuickBooks API HTTP error", "details": str(e)}
    except requests.exceptions.RequestException as e:
        data = {"error": "QuickBooks API request failed", "details": str(e)}

    return JsonResponse(data)


def get_invoice_pdf(request, invoice_id):
    """
    Fetch a QuickBooks Invoice PDF and return it as a file download.
    """

    access_token = refresh_qb_token(request)
    realm_id = request.session.get("qb_realm_id")

    if not access_token or not realm_id:
        return JsonResponse({"error": "QuickBooks not connected or token expired"}, status=400)

    base_url = settings.QBO_BASE_URL  # Example: https://quickbooks.api.intuit.com
    url = f"{base_url}/v3/company/{realm_id}/invoice/{invoice_id}/pdf"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/pdf"
    }

    params = {"minorversion": "75"}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=20)
        print("QBO URL:", response.url)
        response.raise_for_status()

        # SUCCESS → Return PDF file
        return HttpResponse(
            response.content,
            content_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="invoice_{invoice_id}.pdf"'
            }
        )

    except requests.exceptions.HTTPError as e:
        # Unauthorized (token expired)
        if response.status_code == 401:
            return JsonResponse({
                "error": "Unauthorized: Access token may have expired"
            }, status=401)

        return JsonResponse({
            "error": "QuickBooks API HTTP error",
            "status": response.status_code,
            "details": str(e)
        }, status=response.status_code)

    except requests.exceptions.RequestException as e:
        return JsonResponse({
            "error": "QuickBooks API request failed",
            "details": str(e)
        }, status=500)


def get_invoice(request, invoice_id):
    """
    Fetch QuickBooks customers using session-stored tokens.
    """
    access_token = refresh_qb_token(request)
    realm_id = request.session.get('qb_realm_id')

    if not access_token or not realm_id:
        return JsonResponse({"error": "QuickBooks not connected or token expired"}, status=400)

    base_url = settings.QBO_BASE_URL
    url = f"{base_url}/v3/company/{realm_id}/query"
    params = {
        "query": f"select * from Invoice where id = '{invoice_id}'",
        "minorversion": "75"  #
    }
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        print(response.url)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.HTTPError as e:
        if response.status_code == 401:
            data = {"error": "Unauthorized: Access token may have expired"}
        else:
            data = {"error": "QuickBooks API HTTP error", "details": str(e)}
    except requests.exceptions.RequestException as e:
        data = {"error": "QuickBooks API request failed", "details": str(e)}

    return JsonResponse(data)
