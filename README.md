# Euserv_extend_pin
Euserv_extend captcha solver + pin code(Gmail)

## 使用说明

1. 修改 **Euserv_extend.py** 中的用户名，密码

USERNAME: 你的 EUserv 账户邮箱或 Customer ID
```
USERNAME = os.environ.get("EUSERV_USERNAME", "user@gmail.com")  # 用户名或邮箱
USERNAME = os.environ.get("EUSERV_USERNAME", "user1@gmail.com user2@gmail.com") # 多个账号写法
```

PASSWORD: 账户的密码
```
PASSWORD = os.environ.get("EUSERV_PASSWORD", "password")
PASSWORD = os.environ.get("EUSERV_PASSWORD", "password1 password2")
```

2. 配置 TrueCaptcha 验证码接口

默认使用 TrueCaptcha 官方 Demo API。每个 APIKEY 每天有 100 次免费额度，建议自行注册以确保稳定性。

```
TRUECAPTCHA_USERID = 'arun56'
TRUECAPTCHA_APIKEY = 'wMjXmBIcHcdYqO2RrsVN'
```

检查 API 使用次数，一般为 True，保持默认即可
```
TRUECAPTCHA_CHECK_USAGE = True
```

3. 首次运行,开启[Gmail api](https://console.cloud.google.com/apis), 创建 OAuth 2.0 client
    - 下载OAuth2.0 client 重命名为 credentials.json
    - 获取Gmail token
      - python3 gmail_api.py email1 email2 email3 ...
      - 浏览器打开console中链接，登入授权

4. python3 Euserv_extend.py
