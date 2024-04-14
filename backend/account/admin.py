from django.contrib import admin
from .models import User, FamilyDetailModel, ProfilePicModel, WorkInformationModel, DocumentsModel

from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

class ProfilePicInline(admin.StackedInline):
    model = ProfilePicModel
    can_delete = False
    verbose_name = 'Profile picture'

class FamilyDetailInline(admin.StackedInline):
    model = FamilyDetailModel
    can_delete = False
    verbose_name = 'Family Detail'

class WorkInformationInline(admin.StackedInline):
    model = WorkInformationModel
    can_delete = False
    verbose_name = 'Work Permit Information'

class DocumentsInline(admin.StackedInline):
    model = DocumentsModel
    can_delete = False
    verbose_name = 'Documents'

class UserModelAdmin(BaseUserAdmin):
    list_display = ['id', 'email', 'name', 'date_of_birth', 'gender', 'address', 'contact', 'is_admin']
    list_filter = ['is_admin']
    fieldsets = [
        ('User Credentials', {'fields' : ['email', 'password']}),
        ('Personal Information', {'fields': ['name', 'date_of_birth', 'gender', 'address', 'contact', ]}),
        ('Rermissions', {'fields': ['is_admin']}),
                ]

    add_fieldsets = [
        (
            None, 
            {
                'classes': ['wide'],
                'fields': ['email', 'name', 'date_of_birth', 'gender', 'address', 'contact', 'password1', 'password2'],
            },
        ),
                    ]

    search_fields = ['email']
    ordering = ['email', 'id']
    filter_horizontal = []
    inlines = (ProfilePicInline, FamilyDetailInline, WorkInformationInline, DocumentsInline)

admin.site.register(User, UserModelAdmin)


