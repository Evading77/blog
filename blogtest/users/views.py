from django.http import HttpResponseBadRequest, HttpResponse
from django.shortcuts import render
from django.views import View
from libs.captcha.captcha import captcha
from django_redis import get_redis_connection

class RegisterView(View):
    def get(self,request):
        """
        提供注册界面
        :param request: 请求对象
        :return:注册界面
        """
        return render(request,'register.html')


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
