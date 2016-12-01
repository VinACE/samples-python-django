from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required

from .models import DiscoveryDocument, TokenManager, Struct, Profile

import requests, json, sys
from .tokens import token_validation
from .openid import call_token_endpoint

from django.conf import settings


# GLOBALS
okta_config = Struct(**settings.OKTA_JSON)


def scenarios_controller(request):
    # Clear cookies on render
    response = render(request, 'index.mustache', {'oidc': okta_config.oidc, 'user': {}})
    delete_cookies(response)
    return response


def login_redirect_controller(request):
    return render(request, 'index.mustache', {'oidc': okta_config.oidc, 'user': {}})


def login_custom_controller(request):
    return render(request, 'index.mustache', {'oidc': okta_config.oidc, 'user': {}})


def profile_controller(request):
    user = User.objects.get(username=request.user)
    claims = user.profile.tokens.claims
    params = {'email': request.user, 'claims': Struct(**claims)}

    response = render(request, 'index.mustache', {'oidc': okta_config.oidc, 'user': params})
    delete_cookies(response)
    return response


def callback_controller(request):
    # Handles the token exchange from the redirect
    def token_request(auth_code, nonce):
        # Setup Token Request
        token_endpoint = '{}/oauth2/v1/token?'.format(okta_config.oidc['oktaUrl'])

        tokens = call_token_endpoint(token_endpoint, auth_code, okta_config.oidc)
        
        user = None

        if tokens != None:
            if 'id_token' in tokens:
                # Perform token validation
                claims = token_validation(tokens['id_token'], okta_config.oidc, nonce)
                                
                if claims:
                    # Authenticate User
                    user = validate_user(claims)
                    user.profile.tokens.set_id_token(tokens['id_token'])
                    user.profile.tokens.set_claims(claims)

            if 'access_token' in tokens:
                user.profile.tokens.set_access_token(tokens['access_token'])

        return user, user.profile.tokens.get_json()

    if request.POST:
        return HttpResponse('Endpoint not supported')
    
    else:
        state = ""
        nonce = ""
        
        # Get state and nonce from cookie
        if 'okta-oauth-state' in request.COOKIES:
            # Current AuthJS Cookie Setters
            state = request.COOKIES["okta-oauth-state"]
            nonce = request.COOKIES["okta-oauth-nonce"]

        else:
            # Widget Cookie Setters
            if 'okta-oauth-redirect-params' in request.COOKIES:
                cookies = json.loads(request.COOKIES['okta-oauth-redirect-params'])
                if cookies:
                    state = cookies['state']
                    nonce = cookies['nonce']
            else:
                return HttpResponse("Error setting and/or retrieving cookies")

        # Verify state
        if not state or request.GET['state'] != state:
            return HttpResponse("Value {} does not match the assigned state -> {}".format(request.GET['state'], state))
                
        user, token_manager_json = token_request(request.GET['code'], nonce)
        request.session['tokens'] = token_manager_json

        if user is None:
            return redirect('/login')
        
        login(request, user)

        return redirect('/authorization-code/profile')


@login_required(redirect_field_name=None, login_url='/authorization-code/login')
def logout_controller(request):
    logout(request)
    return redirect('/')


def validate_user(claims):
    # Create user for django session
    user = authenticate(
        username=claims['email'],
        password=claims['sub']
    )
    if user is None:
        # Create user
        User.objects.create_user(
            claims['email'],
            claims['email'],
            claims['sub']
        )
        user = authenticate(
            username=claims['email'],
            password=claims['sub']
        )
        profile = Profile()
        profile.user = user
        profile.save()

    return user


def delete_cookies(response):
    # Delete authJS/widget cookies
    response.delete_cookie('okta-oauth-nonce')
    response.delete_cookie('okta-oauth-state')
    response.delete_cookie('okta-oauth-redirect-params')
