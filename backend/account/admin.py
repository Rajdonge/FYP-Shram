from django.contrib import admin
from .models import User, FamilyDetailModel

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['id', 'email']

@admin.register(FamilyDetailModel)
class FamilyDetailAdmin(admin.ModelAdmin):
    list_display = ['father_name', 'mother_name', 'mobile_number']