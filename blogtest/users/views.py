import logging
import re
from random import randint

from django.contrib.auth import login, authenticate
from django.http import HttpResponseBadRequest, HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.views import View
from libs.captcha.captcha import captcha
from django_redis import get_redis_connection

from libs.yuntongxun.sms import CCP
from users.models import User
from utils.response_code import RETCODE

logger=logging.getLogger('django')
class RegisterView(View):
    def get(self,request):
        """
        提供注册界面
        :param request: 请求对象
        :return:注册界面
        """
        return render(request,'register.html')

    def post(self,request):
        # 1、接收参数
        mobile=request.POST.get('mobile')
        password=request.POST.get('password')
        password2=request.POST.get('password2')
        smscode=request.POST.get('sms_code')

        # 2、验证数据
        # 2.1、判断参数是否齐全
        if not all([mobile,password,password2,smscode]):
            return HttpResponseBadRequest('缺少必传参数')

        # 2.2、判断手机号是否合法
        if not re.match(r'^1[3-9]\d{9}$',mobile):
            return HttpResponseBadRequest('请输入正确的手机号码')

        # 2.3、判断密码是否是8-20个字符
        if not re.match(r'^[0-9a-zA-Z]{8,20}$',password):
            return HttpResponseBadRequest('请输入8-20位的密码')
        # 2.4、判断两次密码是否一致
        if password!=password2:
            return HttpResponseBadRequest('两次输入的密码不一致')
        # 2.5、验证短信验证码
        redis_conn=get_redis_connection('default')
        sms_code_server=redis_conn.get('sms:%s' % mobile)

        if sms_code_server is None:
            return HttpResponseBadRequest('短信验证码已过期')
        if smscode!=sms_code_server.decode():
            return HttpResponseBadRequest('短信验证码错误')

        # 3、保存注册数据
        try:
            # create_user可以使用系统的方法对密码进行加密
            user=User.objects.create_user(username=mobile,mobile=mobile,password=password)
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('注册失败')

        # 实现状态保持
        login(request,user)
        # 4、响应注册结果，跳转到首页
        #redirect 是进行重定向
        #reverse 是可以通过namespace:name来获取所对应的路由
        response= redirect(reverse('home:index'))
        # 设置cookie信息，以方便首页中用户信息展示的判断和用户信息的显示
        response.set_cookie('is_login',True)
        #设置用户名有效期一个月
        response.set_cookie('username',user.username,max_age=30*24*3600)

        return response


class ImageCodeView(View):
    def get(self,request):
        # 1. 获取前端传递过来的uuid参数
        uuid=request.GET.get('uuid')

        # 2. 判断uuid参数是否为None
        if uuid is None:
            return HttpResponseBadRequest('请求参数错误！')

        # 3. 通过catcha来生成图片验证码（图片和图片内容）
        # 获取验证码内容和验证码图片二进制数据
        text,image=captcha.generate_captcha()

        # 4. 将图片验内容保存到redis中
        # 设置过期时间
        # uuid作为key，图片内容为一个value
        redis_conn = get_redis_connection('default')

        # key设置为uuid
        # seconds：过期秒数，300秒，5分钟后过期
        # value: text
        redis_conn.setex('img:%s' % uuid, 300, text)

        # 5. 返回响应，将生成的图片以content_type为image/jpeg的形式返回给请求
        return HttpResponse(image,content_type='image/jpeg')

class SmsCodeView(View):
    def get(self,request):
        # 1、接收参数
        image_code=request.GET.get('image_code')
        uuid=request.GET.get('uuid')
        mobile=request.GET.get('mobile')

        logger.info(image_code,uuid,mobile)
        # 2、校验参数
        # 2.1验证参数是否齐全
        if not all([image_code,uuid,mobile]):
            return JsonResponse({'code':RETCODE.NECESSARYPARAMERR,'errmsg':'缺少必传参数！'})

        # 2.2图片验证码的验证
        # 创建连接到redis的对象，连接redis，获取redis中的图片验证码
        redis_conn=get_redis_connection('default')
        # 提取图形验证码
        redis_image_code=redis_conn.get('img:%s' %uuid)
        # 判断图片验证码是否存在
        if redis_image_code is None:
            #图形验证码过期或者不存在
            return JsonResponse({'code':RETCODE.IMAGECODEERR,'errmsg':'图形验证码失效！'})
        # 如果图片验证码未过期，我们获取到之后，就可以删除图片验证码了
        # 删除图形验证码，避免恶意测试图形验证码
        try:
            redis_conn.delete('img:%s' %uuid)
        except Exception as e:
            logger.error(e)
        # 对比图形验证码，注意大小写的问题，redis的数据是bytes类型
        if redis_image_code.decode().lower()!=image_code.lower():
            return JsonResponse({'code':RETCODE.IMAGECODEERR,'errmsg':'输入图形验证码有误！'})
        # 3、生成短信验证码：生成6位数验证码
        sms_code='%06d' % randint(0,999999)
        # 将验证码输出在控制台，以方便调试
        logger.info("短信验证码是： "+sms_code)

        # 4、保存短信验证码到redis中，并设置有效期
        redis_conn.setex('sms:%s' % mobile,300,sms_code)
        # 5、发送短信验证码
        CCP().send_template_sms(mobile,[sms_code,5],1)
        # 6、响应结果
        # 没有注册短信发送的这个，直接返回true
        return JsonResponse({'code':RETCODE.OK,'errmsg':'发送短信成功!'})

class LoginView(View):
    def get(self,request):
        return render(request,'login.html')

    def post(self,request):
        """
        1、接收参数
        2、参数验证
            2.1 验证手机号是否符合规则
            2.2 验证密码是否符合规则
        3.用户认证登录
        4.状态保持
        5.根据用户选择，是否记住登录状态来进行判断
        6、为了首页显示我们需要设置一些cookie信息
        7、返回响应
        :param request:
        :return:
        """
        # 1、接收参数
        mobile=request.POST.get('mobile')
        password=request.POST.get('password')
        remember=request.POST.get('remember')
        # 2、参数验证
        #     2.1 验证手机号是否符合规则
        if not re.match(r'^1[3-9]\d{9}$',mobile):
            return HttpResponseBadRequest('请输入正确的手机号')
        #     2.2 验证密码是否符合规则
        if not re.match(r'^[0-9a-zA-Z]{8,20}$',password):
            return HttpResponseBadRequest('密码最少8位，最长20位')
        # 3.用户认证登录
        # 采用系统自带的认证方法进行认证
        # 如果我们的用户名和密码正确，会返回user
        # 如果我们的用户名或密码不正确，会返回None

        # 默认的认证方法是针对于username字段进行用户名的判断
        # 当前的判断信息是手机号，所以我们需要修改认证字段
        # 需要到User模型中进行修改，等测试出现问题的时候，再修改
        # 认证字段已经在User模型中的USERNAME_FIELD = 'mobile'修改
        user=authenticate(mobile=mobile,password=password)
        if user is None:
            return HttpResponseBadRequest('用户名或密码错误')
        # 4.状态保持
        login(request,user)

        # 5.根据用户选择，是否记住登录状态来进行判断
        # 6、为了首页显示我们需要设置一些cookie信息
        response=redirect(reverse('home:index'))
        if remember !='on':
            #没有记住用户：浏览器会话结束后就过期
            request.session.set_expiry(0)
            #设置cookie
            response.set_cookie('is_cookie',True)
            response.set_cookie('username',user.username,max_age=14*24*3600)
        else:
            #记住用户：None表示两周后过期
            request.session.set_expiry(None)
            # 设置cookie
            response.set_cookie('is_cookie', True,max_age=14*24*3600)
            response.set_cookie('username', user.username, max_age=14 * 24 * 3600)
        # 7、返回响应
        return response






