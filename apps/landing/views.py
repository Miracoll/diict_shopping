from django.shortcuts import render

from apps.core.models import Product


def home(request):
    products = Product.objects.filter(is_active=True).order_by('-created_at')[:8]
    return render(request, 'landing/home.html', {'products': products})
