from django.db import models

    
class OtherImages(models.Model):
    image = models.ImageField(upload_to='otherImages')
    
    
class Canvas(models.Model):
    image = models.ImageField(upload_to='prodpics')
    name = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    medium = models.CharField(max_length=100)
    size = models.CharField(max_length=50)


class Bottles(models.Model):
    image = models.ImageField(upload_to='prodpics')
    name = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    medium = models.CharField(max_length=100)
    
    
class Gallery(models.Model):
    image = models.ImageField(upload_to='prodpics')
    
    
class Testimonials(models.Model):
    image = models.ImageField(upload_to='testimonialpics')
    testimonial = models.TextField()
    name = models.CharField(max_length=50)
    description = models.CharField(max_length=50)
    
    
class Artists(models.Model):
    image = models.ImageField(upload_to='artistpics')
    name = models.CharField(max_length=50)
    title = models.CharField(max_length=50)
    description = models.TextField()
    

class Order(models.Model):
    PRODUCT_TYPE_CHOICES = [
        ('canvas', 'Canvas'),
        ('bottle', 'Bottle'),
    ]
    product_type = models.CharField(max_length=10, choices=PRODUCT_TYPE_CHOICES, default='art')
    product_id = models.PositiveIntegerField(default=0)
    name = models.CharField(max_length=50)
    phone = models.CharField(max_length=30, default='254')
    email = models.CharField(max_length=50)
    address = models.CharField(max_length=50)
    total_price = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    

