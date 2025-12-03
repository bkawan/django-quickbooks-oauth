"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

from quickbooks import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('connect/', views.connect_to_quickbooks),
    path('callback/', views.quickbooks_callback, name='qb_callback'),
    path('customers/', views.get_customers, name='customers'),
    path('customers/<int:id>/', views.get_customer, name='customer'),
    path('company/', views.get_company_info, name='company'),
    path('invoices/', views.get_invoices, name='invoices'),
    path('invoices/<int:invoice_id>/pdf/', views.get_invoice_pdf, name='invoice_pdf'),
    path('invoices/<int:invoice_id>/', views.get_invoice, name='get_invoice'),
]

