from django.shortcuts import render
from django.http import JsonResponse
from json import JSONEncoder
from django.views.decorators.csrf import csrf_exempt
from web.models import Income, Expense, Token, Passwordresetcodes
from datetime import datetime
from django.contrib.auth.models import User
from bestoon import settings
from django.utils.crypto import get_random_string
from django.contrib.auth.hashers import make_password
# google reCaptcha
import requests
import json
import urllib
from os import curdir, sep
from urllib.parse import parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer
# end google reCaptcha
from datetime import datetime




def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')

    return(ip)

def grecaptcha_verify(request):
    data = request.POST
    captcha_rs = data.get('g-recaptcha-response')
    url = settings.SITE_VERIFY_URL
    params = {
        'secret': settings.SECRET_KEY,
        'response': captcha_rs,
        'remoteip': get_client_ip(request)
    }
    verify_rs = requests.get(url, params=params, verify=True)
    verify_rs = verify_rs.json()
    print(verify_rs.get("success", False))
    return(verify_rs.get("success", False))



def index(request):
    context={}
    return render(request, 'index.html', context)

def register(request):
    if 'requestcode' in request.POST.keys():  # form is filled. if not spam, generate code and save in db, wait for email confirmation, return message
        print('form is filled')
        print(request.POST)
        # is this spam? check reCaptcha
        if not grecaptcha_verify(request):  # captcha was not correct
            print('captcha error')

            context = {
                'message': 'کپچای گوگل درست وارد نشده بود. شاید ربات هستید؟ کد یا کلیک یا تشخیص عکس زیر فرم را درست پر کنید. ببخشید که فرم به شکل اولیه برنگشته!'}  # TODO: forgot password
            return render(request, 'register.html', context)

        # duplicate email
        if User.objects.filter(email=request.POST.get('email')).exists():
            print('duplicate email')
            context = {
                'message': 'متاسفانه این ایمیل قبلا استفاده شده است. در صورتی که این ایمیل شما است، از صفحه ورود گزینه فراموشی پسورد رو انتخاب کنین. ببخشید که فرم ذخیره نشده. درست می شه'  # TODO: forgot password
            }

            #TODO: Keep the form data;
            return render(request, 'register.html', context)

        # if user does not exists
        if not User.objects.filter(username=request.POST.get('username')).exists():
            code = get_random_string(length=32)
            now = datetime.now()
            email = request.POST.get('email')
            password = make_password(request.POST.get('password'))
            username = request.POST.get('username')
            temporarycode = Passwordresetcodes(email=email, time=now, code=code, username=username, password=password)
            temporarycode.save()
            #message = PMMail(api_key=settings.POSTMARK_API_TOKEN,
            #                 subject="فعالسازی اکانت بستون",
            #                 sender="jadi@jadi.net",
            #                 to=email,
            #                 text_body=" برای فعال کردن اکانت بستون خود روی لینک روبرو کلیک کنید: {}?code={}".format(
            #                     request.build_absolute_uri('/accounts/register/'), code),
            #                 tag="account request")
            #message.send()
            message = 'ایمیلی حاوی لینک فعال سازی اکانت به شما فرستاده شده، لطفا پس از چک کردن ایمیل، روی لینک کلیک کنید.'
            message = 'قدیم ها ایمیل فعال سازی می فرستادیم ولی الان شرکتش ما رو تحریم کرده (: پس راحت و بی دردسر'
            body = " برای فعال کردن اکانت بستون خود روی لینک روبرو کلیک کنید: <a href=\"{}?code={}\">لینک رو به رو</a> ".format(request.build_absolute_uri('/accounts/register/'), code)
            message = message + body
            context = {
                'message': message }
            return render(request, 'index.html', context)

        else:
            context = {
                'message': 'متاسفانه این نام کاربری قبلا استفاده شده است. از نام کاربری دیگری استفاده کنید. ببخشید که فرم ذخیره نشده. درست می شه'}  # TODO: forgot password
            # TODO: keep the form data
            return render(request, 'register.html', context)

    elif request.GET.get('code'): # user clicked on code
        code = request.GET.get('code')
        if Passwordresetcodes.objects.filter(code=code).exists():  # if code is in temporary db, read the data and create the user
            new_temp_user = Passwordresetcodes.objects.get(code=code)
            newuser = User.objects.create(username=new_temp_user.username, password=new_temp_user.password, email=new_temp_user.email)
            this_token = get_random_string(length=48)
            token = Token.objects.create(user=newuser, token=this_token)
            # delete the temporary activation code from db
            Passwordresetcodes.objects.filter(code=code).delete()
            context = {
                'message': 'اکانت شما ساخته شد. توکن شما {} است. آن را ذخیره کنید چون دیگر نمایش داده نخواهد شد! جدی!'.format(
                    this_token)}
            return render(request, 'index.html', context)

        else:
            context = {
                'message': 'این کد فعال سازی معتبر نیست. در صورت نیاز دوباره تلاش کنید'}
            return render(request, 'register.html', context)

    else:
        context = {'message': ''}
        return render(request, 'register.html', context)


@csrf_exempt
def submit_expense(request):
    """user submited an expense"""

    ## TODO: validate date. user might be fake. token might be fake, amount might be fake...
    this_token = request.POST['token']
    this_user = User.objects.filter(token__token= this_token).get()

    now = datetime.now()

    if 'date' not in request.POST:
        date = datetime.now()
    Expense.objects.create(user= this_user, amount= request.POST['amount'], text= request.POST['text'], date= date)

    print("I'm in submit expense")
    print(request.POST)

    return JsonResponse({
        'status': 'ok'
    }, encoder=JSONEncoder)


@csrf_exempt
def submit_income(request):
    """user submited an income"""

    ## TODO: validate date. user might be fake. token might be fake, amount might be fake...
    this_token = request.POST['token']
    this_user = User.objects.filter(token__token=this_token).get()

    now = datetime.now()

    if 'date' not in request.POST:
        date = datetime.now()

    Income.objects.create(user= this_user, amount= request.POST['amount'], text= request.POST['text'], date= date)
    print("I'm in submit income")
    print(request.POST)

    return JsonResponse({
        'status':'ok'
    }, encoder=JSONEncoder)
