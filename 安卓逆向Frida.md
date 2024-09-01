[TOC]



# 安卓逆向

## openssl

```
cd Desktop    //进入存放openssl文件的目录
openssl x509 -inform DER -in FiddlerRoot.cer -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem
```

## 将证书导入安卓目录

```
adb remount    //获取安卓权限
adb push D:\testzip\269953fb.0 /system/etc/security/cacerts  //将证书导入安卓系统目录
```

## 安卓7.0以上安装Root Explorer

```
http://www.itmop.com/downinfo/13534.html
```

## 开启权限并开启fridaService

```
adb shell
su
cd /data/local/tmp
ls
chmod 777 fridas
./fridas
```

## 非标准端口

```
./fridas -l 127.0.0.1:9999
```

## 转发tcp端口

```
adb forward tcp:27042 tcp:27042
```

## 注入js

```
D:\code\fridaHook     frida -U com.xiaojianbang.app -l Hook.js
```

## 查看进程

```
# 查看进程
frida-ps -R
# 或
frida-ps -U
```

## IDA快捷键

```
F5 查看伪代码

TAB 定位伪代码在ARM中位置

空格键：反汇编窗口切换文本跟图形

CTRL +S ：二进制段的开始地址结束地址
ESC：退到上一个操作地址
G：搜索地址或者符号
N：重命名
分号键：注释
ALT+M ：添加标签
CTRL+M ：列出所有标签
C code  光标地址出内容解析成代码
P ：在函数开始处使用P，从当前地址处解析成函数
D ：data解析成数据
A ：ASCII解析成ASCII
U ：unDefined解析成未定义的内容
X ：查找引用
F5 ：C伪代码
ALT+T ：搜索文本
ALT+B “”搜索16进制
CTRL+ALT+B：打开断点列表 
```

## frida查看手机应用PID

```
frida-ps -U
```

## ab文件解密成apk

```
java -jar ade.jar unpack 1.ab 1.zip
```

## 安装virtualenvwrapper

```
pip install virtualenvwrapper-win -i https://pypi.doubanio.com/simple
```

## 创建虚拟环境

```
mkvirtualenv --python=python.exe全路径 fridaHook
或
virtualenv fridaHook2
```

## 配置虚拟环境变量

```
WORKON_HOME
```

## 进入虚拟环境

```
workon fridaHook
```





## pyhon调用frida

```python
import frida
import sys

rdev = frida.get_remote_device()
process = rdev.enumerate_processes()  # 获取手机所有进程
session = rdev.attach("com.xiaojianbang.app") #获取手机app
#非标准端口进行转发
#session = frida.get_device_manager().add_remote_device('127.0.0.1:9999').attach('com.xiaojianbang.app')


with open('./fridaHook.js',encoding='utf-8')as f:
    script = session.create_script(f.read())


def on_message(message, data):
    if message["type"] == "send":
        print(message['payloay'])


script.on("message", on_message)
script.load()

script.exports.getsign()    #rpc主动调用

sys.stdin.read()
```

## frida-dexdump脱壳

```
frida-dexdump -U -f com.cz.babySister -o d:\testzip\dex
```

## r0captuer抓包

```
python37 r0capture.py -U 好享瘦 -v -p test.pcap
```

## 证书dump

```javascript
//证书绑定
function hook_KeyStore_load() {
    Java.perform(function () {
        var ByteString = Java.use("com.android.okhttp.okio.ByteString");
        var myArray=new Array(1024);
        var i = 0
        for (i = 0; i < myArray.length; i++) {
            myArray[i]= 0x0;
         }
        var buffer = Java.array('byte',myArray);
        
        var StringClass = Java.use("java.lang.String");
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.load.overload('java.security.KeyStore$LoadStoreParameter').implementation = function (arg0) {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));

            console.log("KeyStore.load1:", arg0);
            this.load(arg0);
        };
        KeyStore.load.overload('java.io.InputStream', '[C').implementation = function (arg0, arg1) {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));

            console.log("KeyStore.load2:", arg0, arg1 ? StringClass.$new(arg1) : null);

            if (arg0){
                var file =  Java.use("java.io.File").$new("/sdcard/Download/"+ String(arg0)+".p12");
                var out = Java.use("java.io.FileOutputStream").$new(file);
                var r;
                while( (r = arg0.read(buffer)) > 0){
                    out.write(buffer,0,r)
                }
                console.log("save success!")
                out.close()
            }
            this.load(arg0, arg1);
        };

        console.log("hook_KeyStore_load...");

// android.content.res.AssetManager$AssetInputStream@9b10ad6 bxMAFPL9gc@ntKTqmV@A

// android.content.res.AssetManager$AssetInputStream@41ce8f6 }%2R+\OSsjpP!w%X

// android.content.res.AssetManager$AssetInputStream@54858e6 cods.org.cn

    });
}
//客户端校验服务器（app使用的是系统库）
function hook_ssl() {
    Java.perform(function() {
        var ClassName = "com.android.org.conscrypt.Platform";
        var Platform = Java.use(ClassName);
        var targetMethod = "checkServerTrusted";
        var len = Platform[targetMethod].overloads.length;
        console.log(len);
        for(var i = 0; i < len; ++i) {
            Platform[targetMethod].overloads[i].implementation = function () {
                console.log("class:", ClassName, "target:", targetMethod, " i:", i, arguments);
                //printStack(ClassName + "." + targetMethod);
            }
        }
    });
}


function main(){
    // hook_KeyStore_load()    
    hook_ssl()
}
setImmediate(main);
```

## okhttp-unpinning

```javascript
var classesNames = new Array()
var OkhttpClientClassName = ""
var CertificatePinnerClassName = ""
var prefix = ""

function loadOkhttpClient(){
    Java.perform(function (){
        try{
            Java.use("okhttp3.OkHttpClient")
        }catch(e){
            //console.error(e)
        }
    })
    
}

function loadClasses(){
    Java.perform(function (){
        Java.enumerateLoadedClasses({
            onMatch: function(clsName, handle){
                classesNames.push(clsName)
            },
            onComplete: function(){
                console.log("Search Class Completed!")
            }
        })
    })
}

function findOkhttpClass(){
    Java.perform(function (){
        var Modifier = Java.use("java.lang.reflect.Modifier")
        function isOkhttpClient(clsName){
            if(clsName.split('.').length != 2){
                return false;
            }
            
            try{
                var cls = Java.use(clsName)
                var interfaces = cls.class.getInterfaces()
                const count = interfaces.length
                //console.log(count)
                if(count < 2){
                    return false
                }
                var flag = false
                for(var i = 0; i < count; i++){
                    var interface_ = interfaces[i]
                    var interface_name = interface_.getName()
                    
                    if(interface_name.indexOf("Cloneable") > 0){
                        flag = true
                    }else{
                        if(interface_name.indexOf("$") <= 0){
                            return false
                        }
                    }
                }
                if(!flag) return false;
                

                if(cls.class.getDeclaredClasses().length < 1){
                    return false
                }

                if(cls.class.getSuperclass().getName() != 'java.lang.Object'){
                    return false
                }
                
            }catch(e){
                return false
            }
            return true;
        }

        function isCertificatePinner(clsName,prefix){
            
            if(!clsName.startsWith(prefix)){
                return false
            }

            if(clsName.indexOf("$") > 0){
                return false
            }
            
            if(clsName.split('.').length != 2){
                return false;
            }

            var cls = Java.use(clsName)
            if(cls.class.isInterface()){
                return false
            }

            
            if(cls.class.getInterfaces().length > 0){
                return false
            }

         
            if(cls.class.getDeclaredClasses().length < 1){
                return false
            }
            
            if(cls.class.getSuperclass().getName() != "java.lang.Object"){
                return false
            }

            if(!Modifier.isFinal(cls.class.getModifiers())){
                return false
            }
            var flag = false
            var methods = cls.class.getDeclaredMethods()
            for(var i = 0; i < methods.length; i++){
                var method = methods[i]
                if(method.getParameterCount() < 1){
                    continue
                }
                if(method.getParameterTypes()[0].getName() == "java.security.cert.Certificate"){
                    flag = true
                    break
                }
            }
            if(!flag) return false

            flag = false
            var fields = cls.class.getDeclaredFields()
            for(var k = 0; k < fields.length; k++){
                var field = fields[k];
                if(field.getType().getName() == "java.util.Set"){
                    flag = true
                    break
                }
            }
            if(!flag) return false

            console.log(clsName)
            return true
        }
    
        for(var i = 0; i < classesNames.length; i++){
            if(isOkhttpClient(classesNames[i])){
                OkhttpClientClassName = classesNames[i]
                //console.log(OkhttpClientClassName)
                var splits = classesNames[i].split('.')
                var len = splits.length
                for(var j = 0; j < len-1; j++){
                    prefix = prefix + splits[j] + '.'
                }
            }
        }
        
        for(var i = 0; i < classesNames.length; i++){
            if(isCertificatePinner(classesNames[i],prefix)){
                CertificatePinnerClassName = classesNames[i]
                //console.log(CertificatePinnerClassName)
            }
        }

        console.error("Found Class: "+classesNames.length)
        console.error("Okhttp's package prefix: "+prefix)
        console.error("Find the OkhttpClient: "+OkhttpClientClassName)
        console.error("Find the OkhttpCertificatePinner: "+CertificatePinnerClassName)

        if(OkhttpClientClassName == "" || CertificatePinnerClassName == "" || prefix == ""){
            console.error("Can't find the okhttp class")
            return
        }
    })
}

function hook(){
    Java.perform(function (){
        var Modifier = Java.use("java.lang.reflect.Modifier")
        //TrustAllManager
        var TrustAllManagerClass = Java.registerClass({
            name: "TrustAllManager",
            implements:[Java.use("javax.net.ssl.X509TrustManager")],
            methods: {
                checkClientTrusted(chain, authType) {
                    console.log("checkClientTrusted Called!!")
                },
                checkServerTrusted(chain, authType) {
                    console.log("checkServerTrusted Called!!")
                },
                getAcceptedIssuers() {
                  return [];
                },
              }
        })
        var trustAllManagerHandle = TrustAllManagerClass.$new()

        var sslContext = Java.use("javax.net.ssl.SSLContext").getInstance("TLS")
        sslContext.init(null,Java.array("Ljavax.net.ssl.X509TrustManager;",[trustAllManagerHandle]),null)
        var sslSocketFactory = sslContext.getSocketFactory()

        //HostnameVerify
        var MyHostnameVerify = Java.registerClass({
            name: "MyHostnameVerify",
            implements:[Java.use("javax.net.ssl.HostnameVerifier")],
            methods: {
                verify(hostname, session){
                    console.log(hostname)
                    return true
                }
            }
        })
        var myHostnameVerifyHandle = MyHostnameVerify.$new()
        var BuilderClassName = Java.use(OkhttpClientClassName).class.getDeclaredClasses()[0].getName()
        var OkhttpClient$Buidler = Java.use(BuilderClassName)
    
        var methods = OkhttpClient$Buidler.class.getDeclaredMethods()
        
        for(var i = 0; i < methods.length; i++){
            var method = methods[i]
            if(method.getParameterCount() < 1){
                continue
            }
            if(method.getParameterTypes()[0].getName() == "javax.net.ssl.SSLSocketFactory"){
                var sslSocketFacotryMethodName  = method.getName()
                var len = OkhttpClient$Buidler[sslSocketFacotryMethodName].overloads.length
                for(var j = 0; j < len; j++){
                    OkhttpClient$Buidler[sslSocketFacotryMethodName].overloads[j].implementation = function(SSLSocketFactory){
                        arguments[0] = sslSocketFactory
                        return this[sslSocketFacotryMethodName].apply(this,arguments)
                    }
                }
                console.log(sslSocketFacotryMethodName,"Hooked!")
            }
            if(method.getParameterTypes()[0].getName() == "javax.net.ssl.HostnameVerifier"){
                var hostnameVerifierMethodName = method.getName()
                
                var len = OkhttpClient$Buidler[hostnameVerifierMethodName].overloads.length
                for(var j = 0; j < len; j++){
                    OkhttpClient$Buidler[hostnameVerifierMethodName].overloads[j].implementation = function(hostnameVerifier){
                        arguments[0] = myHostnameVerifyHandle
                        return this[hostnameVerifierMethodName].apply(this,arguments)
                    }
                }
                console.log(hostnameVerifierMethodName, "Hooked!")
            }

            if(method.getParameterTypes()[0].getName() == CertificatePinnerClassName){
                var CertificatePinnerClass = Java.use(CertificatePinnerClassName)
                var certificatePinnerMethodName = method.getName()
                var len = OkhttpClient$Buidler[certificatePinnerMethodName].overloads.length
                for(var j = 0; j < len; j++){
                    OkhttpClient$Buidler[certificatePinnerMethodName].overloads[j].implementation = function(){
                        console.log("certificatePinner add called!")
                        var fields = CertificatePinnerClass.class.getDeclaredFields()
                        for(var k = 0; k < fields.length; k++){
                            var field = fields[k];
                            var modifiers = field.getModifiers()
                            if(Modifier.isFinal(modifiers) && Modifier.isStatic(modifiers) && Modifier.isPublic(modifiers)){
                                arguments[0] = field.get(CertificatePinnerClass.class)
                            }
                        }
                        return this[certificatePinnerMethodName].apply(this,arguments)
                    }
                }
                console.log( method.getName(),"Hooked!")
            }
        }

        var CertificatePinnerClass = Java.use(CertificatePinnerClassName)
        var methods = CertificatePinnerClass.class.getDeclaredMethods()
        for (var i = 0; i < methods.length; i++){
            var method = methods[i]
            if(method.getReturnType().getName() == 'void'){
                var methodName = method.getName()
                console.log(methodName+" Hooked!")
                var m_len = CertificatePinnerClass[methodName].overloads.length
                
                for (var j = 0; j < m_len; j++){
                    if(CertificatePinnerClass[methodName].overloads[j].returnType.name == 'V'){
                        CertificatePinnerClass[methodName].overloads[j].implementation = function(){
                            console.log("certificatePinner check called!")
                        }   
                    }
                }
            }
        }
    })
}

function main(){
    loadOkhttpClient()
    loadClasses()
    findOkhttpClass()
    hook()
}
setImmediate(main)
```

## 需要证书请求

```python
import requests_pkcs12         #版本1.0.8
rsp = requests_pkcs12.post(url, headers=headers, data=data, pkcs12_filename='1.p12',
                                   pkcs12_password='roysue',verify=False)
```

## 安卓应用调用系统

```
String getenv = Os.getenv(key);        //读取环境变量
Os.setenv("name","mxy",true);          //设置环境变量

adb shell
walleye:/ $ export

ANDROID_ASSETS
ANDROID_BOOTLOGO

```

## java byte数组

```java
byte[] arg = "type1v8.10.0.6".getBytes(StandardCharsets.UTF_8);
```

## frida过检测

```
https://www.cnblogs.com/dxmao/articles/17678351.html
```

```javascript
function hook_dlopen() {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    console.log("load " + path);
                }
            }
        }
    );
}

function hook_pthread_create() {
    // console.log("libnesec.so --- " + Process.findModuleByName("libnesec.so").base)
    Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
        onEnter(args) {
            let func_addr = args[2]
            console.log("The thread function address is " + func_addr + Process.findModuleByAddress(func_addr).name);
            if (Process.findModuleByAddress(func_addr).name.indexOf("libnesec.so") != -1){
                Interceptor.replace(args[2],new NativeCallback(function(){
                    console.log("replace success")
                },'void',['void']));
            }
        }
    })
}
function main(){
    // hook_dlopen();
    hook_pthread_create();
}

setImmediate(main);
```

## 过VPN检测

```javascript
function hook_network(){
    Java.perform(function(){
        Java.use("java.net.NetworkInterface").getName.implementation = function(){
            return this.getName().replace("tun0","");
        }
    })
}
```

## root检测（java层）打印堆栈

```javascript
function hook_root(){
     Java.perform(function () {
        function showStacks() {
            console.log(
                Java.use("android.util.Log")
                    .getStackTraceString(
                        Java.use("java.lang.Throwable").$new()
                    )
            );
        }

        Java.use("java.io.File").$init.overload("java.lang.String").implementation = function (str) {
            if (str.toLowerCase().endsWith("/su") || str.toLowerCase() == "su") {
                console.log("发现检测su文件");
                showStacks();
            }
            return this.$init(str);
        }
        Java.use("java.lang.Runtime").exec.overload("java.lang.String").implementation = function (str) {
            if (str.endsWith("/su") || str == "su") {
                console.log("发现尝试执行su命令的行为");
                showStacks();
            }
            return this.exec(str);
        }
        Java.use("java.lang.Runtime").exec.overload("[Ljava.lang.String;").implementation = function (stringArray) {
            for (var i = 0; i < stringArray.length; i++){
                if (stringArray[i].includes("su") || stringArray[i].includes("/su") || stringArray[i] == "su"){
                    console.log("发现尝试执行su命令的行为");
                    showStacks();
                    break;
                }
            }
            return this.exec(stringArray);
        }
        Java.use("java.lang.ProcessBuilder").$init.overload("[Ljava.lang.String;").implementation = function (stringArray){
            for (var i = 0;i < stringArray.length; i++) {
                if (stringArray[i].includes("su") || stringArray[i].includes("/su") || stringArray[i] == "su") {
                    console.log("发现尝试执行su命令的行为");
                    showStacks();
                    break;
                }
            }
            return this.$init(stringArray);
        }
    });   
}

function main(){
    hook_root();
}

setImmediate(main);
```

## 去除强制更新

```javascript
Java.use("android.os.Process").killProcess.implementation = function (a){
    var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
    console.log(stack);
    console.log("killProcess",a);
}
Java.use("java.lang.System").exit.implementation = function (a){
    var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
    console.log(stack);
    console.log("exit",a);
}
```

## so dump

```javascript
function dump_so(so_name) {
    Java.perform(function () {
        var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
        var dir = currentApplication.getApplicationContext().getFilesDir().getPath();
        var libso = Process.getModuleByName(so_name);
        console.log("[name]:", libso.name);
        console.log("[base]:", libso.base);
        console.log("[size]:", ptr(libso.size));
        console.log("[path]:", libso.path);
        var file_path = dir + "/" + libso.name + "_" + libso.base + "_" + ptr(libso.size) + ".so";
        var file_handle = new File(file_path, "wb");
        if (file_handle && file_handle != null) {
            Memory.protect(ptr(libso.base), libso.size, 'rwx');
            var libso_buffer = ptr(libso.base).readByteArray(libso.size);
            file_handle.write(libso_buffer);
            file_handle.flush();
            file_handle.close();
            console.log("[dump]:", file_path);
        }
    });
}
```

## so 修复

```
# 32位so修复
SoFixer_x86.exe -s liblogin_encrypt.so_0xba070000_0xe000.so -o fix.so -m 0xba070000 -d
# 64位so修复
SoFixer_x64.exe -s liblogin_encrypt.so_0xba070000_0xe000.so -o fix.so -m 0xba070000 -d
```

## js中字符串转换

```javascript
function stringToBytes(str){
    return hexToBytes(stringToHex(str));
}

// Convert a ASCII string to a hex string
function stringToHex(str) {
    return str.split("").map(function(c) {
        return ("0" + c.charCodeAt(0).toString(16)).slice(-2);
    }).join("");
}

function hexToBytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

// Convert a hex string to a ASCII string
function hexToString(hexStr) {
    var hex = hexStr.toString();//force conversion
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}
```

## Java层获取系统变量

```java
String getenv = Os.getenv("USER");
//root
```

## native层获取系统变量

```c++
char * name = getenv("name");
//root
```



# ---------------------------------------------

# SO层开发

## 动态注册函数

C++层

```c++
/**
 * 真正执行的JNI函数
 * 注：在C++中要先定义后引用，若先引用后定义则会编译报错
 */
jstring actionKang(JNIEnv *env, jobject thiz, jstring str1) {
    char *cstr = const_cast<char *>(env->GetStringUTFChars(str1, nullptr));
    return env->NewStringUTF(cstr);
}

/**
 * 动态注册的函数集合
 * 第一个参数：Java中的native方法名
 * 第二个参数：传参和返回值类型
 * 第三个参数：native方法所对应的JNI函数
 */
static JNINativeMethod methods[] = {
        {"hello", "(Ljava/lang/String;)Ljava/lang/String;", (void *) actionKang}
};

/**
 * 在Java中调用
 * { System.loadLibrary("此文件生成的so库名"); }
 * 时会触发 JNI_OnLoad 函数
 */
jint JNI_OnLoad(JavaVM *vm, void *args) {
    JNIEnv *env;
    // 获取env，若获取不到则抛出异常
    if (vm->GetEnv((void **) (&env), JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }
    // 调用JNI的类
    jclass mainActivityClass = env->FindClass("com/example/myapplicationdemo/MainActivity");
    env->RegisterNatives(mainActivityClass, methods, sizeof(methods) / sizeof(methods[0]));

    return JNI_VERSION_1_6;
}
```

java层

```java
public native String hello(String str);
```

## C++层开启子线程

```C++
#include <pthread.h>

void myThread() {
    LOG("myThread");
}

pthread_t thread;
pthread_create(&thread, nullptr, reinterpret_cast<void *(*)(void *)>(myThread), nullptr);
```

## LOG日志输出

```c++
#include <android/log.h>

#define TAG "xiaojianbang"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO,"xiaojianbang", __VA_ARGS__);
```

## Native层调用Java对象

```c++
jclass  MessageDigest = env->FindClass("java/security/MessageDigest");
jmethodID jmethodId = env->GetStaticMethodID(MessageDigest,"getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
jobject digest = env->CallStaticObjectMethod(MessageDigest,jmethodId,env->NewStringUTF("md5"));

jmethodID update = env->GetMethodID(MessageDigest,"update", "([B)V");
env->CallVoidMethod(digest,update,data);

jmethodID digest1 = env->GetMethodID(MessageDigest,"digest", "()[B");
jobject result = env->CallObjectMethod(digest,digest1);

jclass MainActivity = env->FindClass("comdta/lesson2/MainActivity");
jmethodID byte2Hex = env->GetMethodID(MainActivity,"byteToHex","([B)Ljava/lang/String;");
jobject string_result = env->CallObjectMethod(thiz,byte2Hex,result);
```

## dlopen函数

```c++
#include <dlfcn.h>
void *dlopen(const char *filename, int flag);    #返回值为so信息
```

## dlsym函数

```c++
#include <dlfcn.h>
void *dlsym(void *handle, const char *symbol);   #handle为dlopen返回值 symbol为函数符号   返回值为函数地址
```



# ---------------------------------------------

# Linux基本命令

安装kali环境

```
https://blog.csdn.net/Qiled/article/details/114859292
```

r0env2022教程

```
https://mp.weixin.qq.com/s/gBdcaAx8EInRXPUGeJ5ljQ
```



```
sudo passwd root           //root
sudo reboot
proxychains curl ip.sb     //查看代理连接状态
nano /etc/proxychains4.conf     //配置代理
nano ~/.bashrc      vim ~/.bashrc     //打开配置
export PATH=/root/Android/Sdk/platform-tools:$PATH       
source ~/.bashrc       //保存
dpkg -i                //安装包
pyenv local system     //切换python2         
npm install --save @types/frida-gum    //下载frida扩展包
jnettop          		//查看网络通信
nautilus /etc            //打开文件夹
grep -ril "mainActivity" *
du -h *                 //查看文件大小
scp -r 要拷贝文件 $user@host:$fname    //拷贝文件到另一台虚拟机
tar -zxvf 压缩包 -C 目标位置   //解压压缩包
vim---------------------------
G  //跳转文档最后
gg  //跳到文档最前
0  $   //行首行尾
/string    按n N  向下向上寻找
yy    复制整行
p     粘贴
dd    删除
u     撤销
vim .gdbinit               //修改文件
:wq                        //保存并推出
i                          //插入
clang---------------------------
clang -target aarch64-linux-android21 hello.c -o hello    //生成可执行elf文件    (-E 预编译   -S编译)
clang -target armv7a-linux-androideabi21 hello.c -o hello
clang -target aarch64-linux-android21 -E hello.c -o hello.i   //预处理
clang -target aarch64-linux-android21 -S hello.i -o hello.s   //编译   （汇编文件）
clang -target aarch64-linux-android21 -C hello.s -o hello.o   //elf文件
clang -target aarch64-linux-android21 -o hello.o hello        //链接
objdump -d hello                                          //dump文件
-------------------------------
clang -emit-llvm -S hello.c -o hello.ll
lli hello.ll
llvm-as hello.ll -o hello.bc
llc hello.bc -o hello1.s   
-------------------------------
netstat -tunlp         //查看端口
echo "kanxue_mxy" > kaxue.txt     //往kanxue.txt中写入
echo "kanxue_mxy" >> kaxue.txt    //追加内容到kanxue.txt
cat kanxue.txt         //查看文件内容
apktool d 3.apk        //反编译apk
apktool b 3 -o 3_mod.apk          //回编译
java -jar uber-apk-signer-1.2.1.jar -a 3_mod.apk --allowResign     //apk签名
adb shell dumpsys window | grep mCurrentFocus      //查看手机顶端页面的全限定类名
kill -l                          //查看信号
------------------pwndbg
gdb-multiarch                     //打开gdb
./gdbserver :11946 ./hello        //开启gdbserver
adb forward tcp:11946 tcp:11946   //转发端口
target remote localhost:11946     //连接手机文件
b *0xaaaaa3e0                     //添加断点
ni                                //单步
hexdump 0x127812             //dump数据
-----------------------
nc -help                   //网络请求
nc www.dtasecurity.cn -C     //发送请求
GET /demo01/getNotice Http/1.1
Host: www.dtasecurity.cn
```

## apt下载工具失败

```
wget https://http.kali.org/kali/pool/main/k/kali-archive-keyring/kali-archive-keyring_2018.1_all.deb
apt install ./kali-archive-keyring_2018.1_all.deb
安装完证书后再执行apt-get update和apt-get upgrade即可
```



# ---------------------------------------------

# Java基础

## MD5实现

```java
public String md5Java(byte[] data){
    try {
        MessageDigest digest = MessageDigest.getInstance("md5");
        digest.update(data);
        byte[] digest1 = digest.digest();
        return byteToHex(digest1);
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
    return null;
}

public String byteToHex(byte[] data){
    StringBuilder sb = new StringBuilder();
    for(byte b : data){
        String s = Integer.toHexString(b & 0xFF);
        if(s.length()<2){
            sb.append("0");
        }
        sb.append(s);
    }
    return sb.toString();
}
```



# ----------------------------------------------

# Frida JAVA层HOOK

## Hook博客

```
https://mp.weixin.qq.com/s/OXC-su0Aw1OIZGA67nWz3g
```

## Hook中类型转换

```javascript
var String = Java.use("java.lang.String");
var v = Java.cast(variable, String);
```

## Hook遍历java数组

```javascript
ClassName.func.implementation = function(arg1){
	// 假设arg1是一个数组类型的参数
	for(var i=0; i<arg1.length;i++){
		console.log(arg1[i]);
	}
```

## Hook普通函数

```javascript
function hookTest1(){
    var utils = Java.use("com.xiaojianbang.app.Utils");
    utils.getCalc.implementation = function(a, b){
        a = 123;
        b = 456;
        var retval = this.getCalc(a, b);
        console.log(a, b, retval);
        return retval;
    };
}
```

## Hook重载函数

```javascript
function hookTest2(){
    var utils = Java.use("com.xiaojianbang.app.Utils");
    var money = Java.use("com.xiaojianbang.app.Money");
    utils.test.overload('int').implementation = function(a){
        a = 888;
        var retval = this.test(money.$new("日元", 100000));//对象实例化
        console.log(a, retval);
        return retval;
    };
    utils.test.overload().implementation = function(){
        var retval = this.test();
        console.log(retval);
        return retval;
    };
    utils.test.overload('com.xiaojianbang.app.Money').implementation = function(a){
        var retval = this.test(a);
        console.log(retval);
        return retval;
    };
}
```

## Hook方法的所有重载

```javascript
function hookTest3(){
    var utils = Java.use("com.xiaojianbang.app.Utils");
    //console.log(utils.test.overloads.length);
    for(var i = 0; i < utils.test.overloads.length; i++){
        utils.test.overloads[i].implementation = function(){
            //console.log(JSON.stringify(arguments));

            if(arguments.length == 0){
                return "调用了没有参数的";
            }else if(arguments.length == 1){
                if(JSON.stringify(arguments).indexOf("Money") != -1){
                    return "调用了Money参数的";
                }else{
                    return "调用了int参数的";
                }
            }

            //arguments[0] = 1000;
            //return this.test.apply(this, arguments);
        };
    }
}
```

## Hook构造函数

```javascript
function hookTest4(){
    var money = Java.use("com.xiaojianbang.app.Money");
    money.$init.overload('java.lang.String', 'int').implementation = function(str, num){
        console.log(str, num);
        str = "欧元";
        num = 2000;
        this.$init(str, num);
    };
}
```

## 修改类的字段

```javascript
function hookTest5(){
    Java.perform(function(){
        //静态字段的修改
        var money = Java.use("com.xiaojianbang.app.Money");
        //console.log(JSON.stringify(money.flag));
        money.flag.value = "mxy";
        console.log(money.flag.value);

        //非静态字段的修改
        Java.choose("com.xiaojianbang.app.Money", {
            onMatch: function(obj){
                obj._name.value = "ouyuan"; //字段名与函数名相同 前面加个下划线
                obj.num.value = 150000;
            },
            onComplete: function(){

            }
        });
    });
}
```

## hook内部类和匿名类

```javascript
function hookTest6(){
    Java.perform(function(){
        var innerClass = Java.use("com.xiaojianbang.app.Money$innerClass");
        // console.log(innerClass);
        innerClass.$init.implementation = function(a,b){
            a = "mxy";
            b=88888;
            return this.$init(a,b);
        };
    });
}
```

## 枚举所有类以及类的所有方法

```JavaScript
function hookTest7(){
    Java.perform(function(){
        //枚举已经加载过的类
        // Java.enumerateLoadedClasses({
        //     onMatch:function(name,handle){
        //         if(name.indexOf("com.xiaojianbang.app")!=-1){
        //             console.log(name);
        //             var clazz = Java.use(name);
        //             console.log(clazz);
        //             var method = clazz.class.getDeclaredMethods();
        //             // console.log(method);
        //             for(var i =0;i<method.length;i++){
        //                 console.log(method[i]);
        //             }
        //         }
        //     },
        //     onComplete:function(){

        //     }
        // });

        //枚举同步的加载的类的所有方法
        var classes = Java.enumerateLoadedClassesSync();
        for (var i=0;i<classes.length;i++){
            if(classes[i].indexOf("com.xiaojianbang.app")!=-1){
                var clazz = Java.use(classes[i]);
                    console.log(clazz);
                    var method = clazz.class.getDeclaredMethods();
                    for(var j =0;j<method.length;j++){
                        console.log(method[j]);
                    }
            }
        }

    });
}
```

## hook类的所有方法

```JavaScript
function hookTest8(){
    Java.perform(function(){
        var md5 = Java.use("com.xiaojianbang.app.MD5");
        var methods = md5.class.getDeclaredMethods();
        for(var j = 0; j < methods.length; j++){
            var methodName = methods[j].getName();
            console.log(methodName);

            for(var k = 0; k < md5[methodName].overloads.length; k++){

                md5[methodName].overloads[k].implementation = function(){
                    for(var i = 0; i < arguments.length; i++){
                        console.log(arguments[i]);
                    }
                    return this[methodName].apply(this, arguments);
                };
            }
        }
    });
}
```

## Hook动态加载的dex

```JavaScript
function hookTest9(){
    Java.perform(function(){
        Java.enumerateClassLoaders({
            onMatch: function(loader){
                try {
                    if(loader.loadClass("com.xiaojianbang.app.Dynamic")){
                        Java.classFactory.loader = loader;
                        var Dynamic = Java.use("com.xiaojianbang.app.Dynamic");
                        console.log(Dynamic);
                        Dynamic.sayHello.implementation = function(){
                            return "xiaojianbang";
                        }
                    }  
                } catch (error) {
                    
                }
            },
            onComplete: function(){

            }
        });
    });
}
```

## Java特殊类型的遍历与修改

```JavaScript
function hookTest10(){
    Java.perform(function(){
        var ShufferMap = Java.use("com.xiaojianbang.app.ShufferMap");
        console.log(ShufferMap);
        //Hook show方法
        ShufferMap.show.implementation = function(map){
            console.log(JSON.stringify(map));
            //Java map的遍历
            // var key = map.keySet();
            // var it = key.iterator();
            // var result = "";
            // while(it.hasNext()){
            //     var keystr = it.next();
            //     var valuestr = map.get(keystr);
            //     result += valuestr;
            // }
            // console.log(result);
            // return result;


            map.put("pass","mxy");
            map.put("太原理工大学","www.tyut.com");

            var retval =  this.show(map);
            console.log(retval);
            return retval;
        };
    
    });
}
```

## Java层主动调用

```JavaScript
function hookTest11(){
    Java.perform(function(){
        //静态方法的主动调用
        var rsa = Java.use("com.xiaojianbang.app.RSA");
        var str = Java.use("java.lang.String");
        var base64 = Java.use("android.util.Base64");
        var bytes = str.$new("xiaojianbang").getBytes();
        console.log(JSON.stringify(bytes));
        var retval = rsa.encrypt(bytes);
        var result = base64.encodeToString(retval, 0);
        console.log(result);
        //非静态方法的主动调用1 (新建一个对象去调用)
        var res = Java.use("com.xiaojianbang.app.Money").$new("日元", 300000).getInfo();
        console.log(res);
        var utils = Java.use("com.xiaojianbang.app.Utils");
        res = utils.$new().myPrint(["xiaojianbang","is very good"," ","zygx8","is very good"]);
        console.log(res);
        //非静态方法的主动调用2 (获取已有的对象调用)
        Java.choose("com.xiaojianbang.app.Money",{
            onMatch: function(obj){
                if(obj._name.value == "美元"){
                    res = obj.getInfo();
                    console.log(res);
                }
            },
            onComplete: function(){

            }
        });

    });
}
```

## 打印Java层函数堆栈

```JavaScript
function hookTest12(){
    // .overload()
    // .overload('[B')
    // .overload('[B', 'int', 'int')
    function showStacks(){
        
        //var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
        var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
        console.log(stack);
        
    }
    Java.perform(function(){
        //Java.cast() 强制类型转换
        //Java.openClassFile();
        //Java.registerClass
        //Java.array() 构造任意类型的数组
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.digest.overload().implementation = function(){
            showStacks();
            return this.digest();
        }

    });
}
```

## 用Frida注入dex文件

```javascript
function hookTest13(){
    Java.perform(function(){
        
        Java.openClassFile("/data/local/tmp/xiaojianbang.dex").load();  //参数是安卓端文件的位置
        var xiaojianbang = Java.use("com.xiaojianbang.test.xiaojianbang");

        var ShufferMap = Java.use("com.xiaojianbang.app.ShufferMap");
        ShufferMap.show.implementation = function(map){
            var retval = xiaojianbang.sayHello(map);
            console.log(retval);
            return retval;
        }

    });
}
```

## hook Toast

```java
function hook_toast(){
    var toast = Java.use("android.widget.Toast");
    toast.show.implementation = function (){
        var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
        console.log(stack);
        return this.show();
    }
}
```

## hook hashmap

```javascript
function hook_hashmap(){
    var hashMap = Java.use("java.util.HashMap");
    hashMap.put.implementation = function (a, b) {
        if (a == 'X-API-SIGNATURE'){
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
            console.log(stack);
            console.log("a:", a, "b:", b);
        }

        return this.put(a, b);
    }

}
```



# Frida SO层HOOK

## 常用API

```javascript
// 获取有符号函数的地址
var helloAddr = Module.findExportByName("libxiaojianbang.so", "Java_com_xiaojianbang_app_NativeHelper_add");
// 获取so的基址
var soAddr = Module.findBaseAddress("libxiaojianbang.so"); 返回值是so的基址
var module = Process.getModuleByName("libxiaojianbang.so") 返回值是module对象
// 查看内存的内容
hexdump(ptr(0x74231b1570))
// 将16进制转换成10进制
args[2] = 0x20
args[2].toInt32()
// 函数地址计算
	32位 --> 一般不需要加1
    64位 --> 需要加1
// 将0x74231b1570 转换为指针
    ptr(0x74231b1570)
// 将内存地址赋予可读可写可执行权限    将opcode换成汇编代码
    Memory.protect(codeAddr,4,'rwx');
    codeAddr.writeByteArray(hexToBytes("0001094b"));    //sub w0, w8, w9
// 将对应地址nop
	new Arm64Writer(soAddr.add(0x167c)).putNop();
// 
```

## 枚举导入导出表（so层）

```JavaScript
function hookTest1(){
	
    //枚举导入表
    // var imports = Module.enumerateImports("libxiaojianbang.so");
    // for(var i = 0; i < imports.length; i++){
    //     if(imports[i].name == "strncat"){
    //         console.log(JSON.stringify(imports[i]));
    //         console.log(imports[i].address);
    //     }
    // }

    //枚举导出表
    // var exports = Module.enumerateExports("libxiaojianbang.so");
    // for(var i = 0; i < exports.length; i++){
    //     //if(exports[i].name == "strncat"){
    //         console.log(JSON.stringify(exports[i]));

    //     //}
    // }

    // var helloAddr = Module.findExportByName("libxiaojianbang.so", "Java_com_xiaojianbang_app_NativeHelper_helloFromC");
    // console.log(helloAddr);

}
```

## 枚举符号表

```javascript
function hook_symbols(){
    var symbols = Module.enumerateExports("libencryptlib.so");
    for(var i = 0; i < symbols.length; i++) {
        console.log(symbols[i].name+' '+symbols[i].address);
    }
}
```

## Hook导出函数

```JavaScript
function hookTest2(){
    //获取地址
    var helloAddr = Module.findExportByName("libxiaojianbang.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    console.log(helloAddr);
    if(helloAddr != null){
        Interceptor.attach(helloAddr,{
            onEnter: function(args){
                console.log(args[0]);
                console.log(args[1]);
                console.log(args[2]);
                console.log(args[3]);
                console.log(args[4].toInt32());
            },
            onLeave: function(retval){
                console.log(retval);
                console.log("retval", retval.toInt32());
            }
        });
    } 
}
```

## 修改导入导出寄存器函数参数返回值

```javascript
function hookTest3(){
    var helloAddr = Module.findExportByName("libxiaojianbang.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    console.log(helloAddr);
    if(helloAddr != null){
        Interceptor.attach(helloAddr,{
            onEnter: function(args){
                args[2] = ptr(1000); //new NativePointer()
                console.log(args[2].toInt32());
                console.log(args[3]);
                console.log(args[4]);
            },
            onLeave: function(retval){
                retval.replace(20000);
                console.log("retval", retval.toInt32());
            }
        });
    }
}
```

## 读写内存数据

```JavaScript
function hookTest7(){
    var soAddr = Module.findBaseAddress("libxiaojianbang.so");
    var funcAddr = soAddr.add(0x2764);
    ptr(funcAddr).writeByteArray(stringToBytes('helloword'));
    if(soAddr != null){
        console.log(soAddr.add(0X2764).readCString());
        // console.log(hexdump(soAddr.add(0x2C00)));  //读取指定地址的字符串

        var strByte = soAddr.add(0X2764).readByteArray(16); //读内存
        console.log(strByte);
        
        soAddr.add(0X2764).writeByteArray(stringToBytes("xiao")); //写内存
        // console.log(hexdump(soAddr.add(0X2764)));  //dump指定内存

        // var bytes = Module.readByteArray(soAddr.add(0X2764), 16);
        // console.log(bytes);

        // Interceptor.attach(soAddr,{
        //     onEnter: function(args){
        //         this.args1 = args[1];
        //     },
        //     onLeave: function(retval){
        //         this.args1.writeByteArray(hexToBytes("0123456789abcdef0123456789abcdef")); //修改十六进制
        //         console.log(hexdump(this.args1));
        //     }
        // });

    }
}
```

## 获取指针参数返回值

```javascript
function hookTest5(){
    var soAddr = Module.findBaseAddress("libxiaojianbang.so");
    console.log(soAddr);
    var sub_930 = soAddr.add(0x930); //函数地址计算 thumb+1 ARM不加
    console.log(sub_930);

    // if(sub_930 != null){
    //     Interceptor.attach(sub_930,{
    //         onEnter: function(args){
    //             console.log("args[0]:", "\r\n", hexdump(args[0]));
    //             console.log(args[1].readCString());
    //             console.log(args[2].toInt32());
    //         },
    //         onLeave: function(retval){
    //             console.log("retval:", "\r\n", hexdump(retval));
    //         }
    //     });
    //  }

     var sub_208C = soAddr.add(0x208C); //函数地址计算 thumb+1 ARM不加
     console.log(sub_208C);
     if(sub_208C != null){
        Interceptor.attach(sub_208C,{
            onEnter: function(args){
                this.args1 = args[1];
            },
            onLeave: function(retval){
                //this.args1.writeByteArray(hexToBytes("0123456789abcdef0123456789abcdef"));
                console.log(hexdump(this.args1));
            }
        });
     }
}
```

## Hook_dlopen

```javascript
function hook_dlopen() {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    console.log("load " + path);
                }
            }
        }
    );
}
```

## Hook_dlopen(小肩膀版)

```javascript
function hookTest6(){
    var dlopen = Module.findExportByName(null, "dlopen");
    console.log(dlopen);
    if(dlopen != null){
        Interceptor.attach(dlopen,{
            onEnter: function(args){
                var soName = args[0].readCString();
                console.log(soName);
                if(soName.indexOf("libxiaojianbang.so") != -1){
                    this.hook = true;
                }
            },
            onLeave: function(retval){
                if(this.hook) { hookTest5() };
            }
        });
    }

    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    console.log(android_dlopen_ext);
    if(android_dlopen_ext != null){
        Interceptor.attach(android_dlopen_ext,{
            onEnter: function(args){
                var soName = args[0].readCString();
                console.log(soName);
                if(soName.indexOf("libxiaojianbang.so") != -1){
                    this.hook = true;
                }
            },
            onLeave: function(retval){
                if(this.hook) { hookTest5() };
            }
        });
    }

}
```

## Hook未导出函数

```javascript
function hookTest4(){
    var soAddr = Module.findBaseAddress("libxiaojianbang.so");
    console.log(soAddr);
    var funcAddr = soAddr.add(0x23F4); //函数地址计算 thumb+1 ARM不加
    console.log(funcAddr);

    if(funcAddr != null){
        Interceptor.attach(funcAddr,{
            onEnter: function(args){
    
            },
            onLeave: function(retval){
                console.log(hexdump(retval));
            }
        });
     }

}
```

## jni函数主动调用

```javascript
function hookTest8(){
    var funcAddr = Module.findExportByName("libxiaojianbang.so", "Java_com_xiaojianbang_app_NativeHelper_helloFromC");
    console.log(funcAddr);
    if(funcAddr != null){
        Interceptor.attach(funcAddr,{
            onEnter: function(args){

            },
            onLeave: function(retval){
                var env = Java.vm.tryGetEnv();
                var jstr = env.newStringUtf("www.zygx8.com");  //主动调用jni函数 cstr转jstr
                retval.replace(jstr);
                var cstr = env.getStringUtfChars(jstr); //主动调用 jstr转cstr
                console.log(cstr.readCString());
                console.log(hexdump(cstr));
            }
        });
    }
}
```

## HookJNI函数

```javascript
function hookTest9(){
    Java.perform(function(){
        //console.log(JSON.stringify(Java.vm.tryGetEnv()));
        var envAddr = ptr(Java.vm.tryGetEnv().handle).readPointer();
        var newStringUtfAddr = envAddr.add(0x538).readPointer();
        var registerNativesAddr = envAddr.add(1720).readPointer();
        console.log("newStringUtfAddr", newStringUtfAddr);
        console.log("registerNativesAddr", registerNativesAddr)
        if(newStringUtfAddr != null){
            Interceptor.attach(newStringUtfAddr,{
                onEnter: function(args){
                    console.log(args[1].readCString());
                },
                onLeave: function(retval){

                }
            });
        }
        if(registerNativesAddr != null){     //Hook registerNatives获取动态注册的函数地址
            Interceptor.attach(registerNativesAddr,{
                onEnter: function(args){
                    console.log(args[2].readPointer().readCString());
                    console.log(args[2].add(Process.pointerSize).readPointer().readCString());
                    console.log(args[2].add(Process.pointerSize * 2).readPointer());
                    console.log(hexdump(args[2]));
                    console.log("sub_289C", Module.findBaseAddress("libxiaojianbang.so").add(0x289C));
                },
                onLeave: function(retval){

                }
            });
        }

    });
}
```

## HookJNI（libart.so）

```javascript
function hookTest10(){
    var artSym = Module.enumerateSymbols("libart.so");
    var NewStringUTFAddr = null;
    for(var i = 0; i < artSym.length; i++){
        if(artSym[i].name.indexOf("CheckJNI") == -1 && artSym[i].name.indexOf("NewStringUTF") != -1){
            console.log(JSON.stringify(artSym[i]));
            NewStringUTFAddr = artSym[i].address;
        }
    };

    if(NewStringUTFAddr != null){
        Interceptor.attach(NewStringUTFAddr,{
            onEnter: function(args){
                console.log(args[1].readCString());
            },
            onLeave: function(retval){

            }
        });
    }

}
```

## 打印so层函数堆栈

```javascript
onEnter: function(args){
    if(args[2].readPointer().readCString() == "encode"){
        console.log(args[2].readPointer().readCString());
        console.log(args[2].add(Process.pointerSize).readPointer().readCString());
        console.log(args[2].add(Process.pointerSize * 2).readPointer());
        console.log('CCCryptorCreate called from:\n' +
                    Thread.backtrace(this.context, Backtracer.FUZZY)
                    .map(DebugSymbol.fromAddress).join('\n') + '\n');
    }
},
    onLeave: function(retval){

    }
```

## so层函数主动调用

```javascript
function hookTest11(){
    Java.perform(function(){
        var funcAddr = Module.findBaseAddress("libxiaojianbang.so").add(0x23F4);
        var func = new NativeFunction(funcAddr, "pointer", ['pointer', 'pointer']);
        var env = Java.vm.tryGetEnv();
        console.log("env: ", JSON.stringify(env));
        if(env != null){
            var jstr = env.newStringUtf("xiaojianbang is very good!!!");
            //console.log("jstr: ", hexdump(jstr));
            var cstr = func(env, jstr);
            console.log(cstr.readCString());
            console.log(hexdump(cstr));
        }
    });
}
```

## frida读写文件

```javascript
//frida API 读写文件
function hookTest12(){
    var ios = new File("/sdcard/xiaojianbang.txt", "w");
    ios.write("xiaojianbang is very good!!!\n");
    ios.flush();
    ios.close();
}
//Hook libc 读写文件
function hookTest13() {

    var addr_fopen = Module.findExportByName("libc.so", "fopen");
    var addr_fputs = Module.findExportByName("libc.so", "fputs");
    var addr_fclose = Module.findExportByName("libc.so", "fclose");

    console.log("addr_fopen:", addr_fopen, "addr_fputs:", addr_fputs, "addr_fclose:", addr_fclose);
    var fopen = new NativeFunction(addr_fopen, "pointer", ["pointer", "pointer"]);
    var fputs = new NativeFunction(addr_fputs, "int", ["pointer", "pointer"]);
    var fclose = new NativeFunction(addr_fclose, "int", ["pointer"]);

    var filename = Memory.allocUtf8String("/sdcard/xiaojianbang.txt");
    var open_mode = Memory.allocUtf8String("w");
    var file = fopen(filename, open_mode);
    console.log("fopen:", file);

    var buffer = Memory.allocUtf8String("zygxb\n");
    var retval = fputs(buffer, file);
    console.log("fputs:", retval);

    fclose(file);

}
```

## 主动调用so层函数

```javascript
var method02_addr = Module.findExportByName('libnative-lib.so','Java_com_roysue_easymd5_MainActivity_method02');
    console.log(method02_addr);

var method02 = new NativeFunction(method02_addr,'pointer',['pointer','pointer','pointer']);
Java.perform(function(){
    var jstring = Java.vm.getEnv().newStringUtf('4e8de2f3c674d8157b4862e50954d81c');
    var result = method02(Java.vm.getEnv(),jstring,jstring);
    console.log(Java.vm.getEnv().getStringUtfChars(result,null).readCString());
```

## hookARM指令

```javascript
function inline_hook() {
    var base_hello_jni = Module.findBaseAddress("libxxxx.so");
    console.log("base_hello_jni:", base_hello_jni);
    if (base_hello_jni) {
        console.log(base_hello_jni);
        //inline hook
        var addr_07320 = base_hello_jni.add(0x07320);//指令执行的地址，不是变量所在的栈或堆
        Interceptor.attach(addr_07320, {
            onEnter: function (args) {
                console.log("addr_07320 x13:", Memory.readCString(this.context.x13));//注意这里是怎么得到寄存器值的
            }, onLeave: function (retval) {
            }
        });
    }
}
```

## hook_RegisterNatives

```javascript
function hook_RegisterNatives() {
    var symbols = Module.enumerateSymbolsSync("libart.so");
    var addrRegisterNatives = null;
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];

        //_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
        if (symbol.name.indexOf("art") >= 0 &&
            symbol.name.indexOf("JNI") >= 0 &&
            symbol.name.indexOf("RegisterNatives") >= 0 &&
            symbol.name.indexOf("CheckJNI") < 0) {
            addrRegisterNatives = symbol.address;
            console.log("RegisterNatives is at ", symbol.address, symbol.name);
        }
    }

    if (addrRegisterNatives != null) {
        Interceptor.attach(addrRegisterNatives, {
            onEnter: function (args) {
                //console.log("[RegisterNatives] method_count:", args[3]);
                var env = args[0];
                var java_class = args[1];
                var class_name = Java.vm.tryGetEnv().getClassName(java_class);

                var methods_ptr = ptr(args[2]);

                var method_count = parseInt(args[3]);
                for (var i = 0; i < method_count; i++) {
                    var name_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3));
                    var sig_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize));
                    var fnPtr_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2));

                    var name = Memory.readCString(name_ptr);
                    var sig = Memory.readCString(sig_ptr);
                    var find_module = Process.findModuleByAddress(fnPtr_ptr);
                    console.log("[RegisterNatives] java_class:", class_name, "name:", name, "sig:", sig, "fnPtr:", fnPtr_ptr, "module_name:", find_module.name, "module_base:", find_module.base, "offset:", ptr(fnPtr_ptr).sub(find_module.base));

                }
            }
        });
    }
}

setImmediate(hook_RegisterNatives);
```

## hook静态注册

```javascript
function hook_art(){
    var dlsymAddr = Module.findExportByName(null,'dlsym');
    Interceptor.attach(dlsymAddr,{
        onEnter:function(args){
            this.funcName = args[1].readCString();
        },onLeave:function(retval){
            var moudle = Process.findModuleByAddress(retval);
            if(moudle){
                console.log(Process.findModuleByAddress(retval).name +" " +this.funcName+" "+retval.sub(moudle.base));
            }
        }
    })
}
```



## inline_hook

```javascript
function inline_hook() {
    var base_hello_jni = Module.findBaseAddress("libhello-jni.so");
    console.log("base_hello_jni:", base_hello_jni);
    if (base_hello_jni) {
        console.log(base_hello_jni);
        //inline hook
        var addr_07320 = base_hello_jni.add(0x07320);
        Interceptor.attach(addr_07320, {
            onEnter: function (args) {
                console.log("addr_07320 x13:", this.context.x13);
            }, onLeave: function (retval) {
            }
        });
    }
}
```

## hook静态注册函数所在的so

```javascript
function hook_dlsym() {
    let dlsymAddr = Module.findExportByName('libbase.so', 'dlsym')
    console.log(dlsymAddr)
    Interceptor.attach(dlsymAddr, {
        onEnter: function (args) {
            this.args1 = args[1]
        },
        onLeave: function (retval) {
            let module = Process.findModuleByAddress(retval)
            if (module == null) {return retval;}
            // console.log(this.args1.readCString(), module.name, retval, retval.sub(module.base))
            var functionName = this.args1.readCString();
            if(functionName.indexOf("GetSig")!==-1){
                console.log(module.name,module.base);
                console.log("\t",functionName);
            }
            return retval;
        },
    })
}
```



# ---------------------------------------

# Inline hook

```
-函数替换&&函数附加
-定向跳转
-寄存器保存
-函数复原
```



# objection

## 文档

```
https://www.anquanke.com/post/id/197657#h2-0
```

## 调用插件

```
objection -g com.android.settings explore -P ~/.objection/plugins
```

## 查看当前可用的activity

```
android hooking list activities
```

## 启动时注入

```
objection -g packageName explore --startup-command "android hooking watch xxx"
```

## 直接启动activity

```
android intent launch_activity com.android.settings.DisplaySettings
```

## 在堆上搜索实例

```
android heap search instances com.android.settings.DisplaySettings
```

## 调用实例方法

```
android heap execute 0x2526 getPreferenceScreenResId
```

## 列出内存中所有的类

```
android hooking list classes
```

## 内存中搜索所有的类

```
android hooking search classes display 
```

## 内存中搜索所有的方法

```
android hooking search methods display
```

## 直接生成`hook`代码

```
android hooking generate  simple  com.android.settings.DisplaySettings
```

## hook类的所有方法

```
android hooking watch class android.bluetooth.BluetoothDevice
```

## 列出类的所有方法

```
android hooking list class_methods com.android.settings.DisplaySettings
```

## hook方法的参数、返回值和调用栈

```
android hooking watch class_method android.bluetooth.BluetoothDevice.getName --dump-args --dump-return --dump-backtrace
```

## 搜索相关类

```
android hooking search classes search sun.util.logging.LoggingProxy
```

## Hook手机的设置

```
#查看一下“设置”应用的包名
frida-ps -U|grep -i setting
#objection注入“设置”应用
objection -g com.android.settings explore
```

## 查看内存中加载的库

```
memory list modules
```

## 查看库的导出函数

```
memory list exports libssl.so
```

## 过证书绑定

```
android sslpinning disable
```



# unidbg的使用

## hook调试命令

```
c：继续
n：跨过
bt：调用堆栈

st hex：搜索堆栈
shw hex:搜索可写堆
shr hex：搜索可读堆
shx-hex：搜索可执行堆

nb：在下一个街区破发
s|si:步入
s[decimal]：执行指定的金额指令
s（blx）：执行util blx助记符，性能低

m（op）[size]：显示内存，默认大小为0x70，大小可以是十六进制或十进制
mr0-mr7，mfp，mip，msp[size]：显示指定寄存器的内存
m（address）[size]：显示指定地址的内存，地址必须以0x开头

wr0-wr7，wfp，wip，wsp＜value＞：写入指定寄存器
wb（address）,ws（address）,wi（address）＜value＞：写入指定地址的（字节、短、整数）内存，地址必须以0x开头
wx（address）＜hex＞：将字节写入指定地址的内存，地址必须以0x开头

b（address）：添加临时断点，地址必须以0x开头，可以是模块偏移量
b：添加寄存器PC的断点
r：删除寄存器PC的断点
blr：添加寄存器LR的临时断点

p (assembly):位于PC地址的修补程序集
where: 显示java堆栈跟踪
trace[begin-end]：设置跟踪指令
traceRead[begin-end]：设置跟踪内存读取
traceWrite〔begin-end〕：设置跟踪内存写入
vm：查看加载的模块
vbs：查看断点
d|dis:显示反汇编
d（0x）：在指定地址显示反汇编
stop: 停止模拟
run[arg]：运行测试
gc：运行System.gc（）
threads: 显示线程列表
cc size：将asm从0x4000c364-0x4000c364+size字节转换为c函数
```

## 补安卓系统环境变量

```java
//在AndroidElfLoader类中添加相应的环境变量
this.environ = initializeTLS(new String[] {
    "ANDROID_DATA=/data",
    "ANDROID_ROOT=/system",
    "PATH=/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin",
    "NO_ADDR_COMPAT_LAYOUT_FIXUP=1"
});
```



## 补环境

### 1.入参

```java
List<Object> arg_list = new ArrayList<>(10);
arg_list.add(vm.getJNIEnv());
arg_list.add(0);

// string类型
StringObject str1 = new StringObject(vm,"123456");
arg_list.add(vm.addLocalObject(str1));

// long类型
long num1 = 0;
arg_list.add(num1);

// context类型
DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);
arg_list.add(vm.addLocalObject(context));

// byte[] 类型
byte[] b1 = "123456".getBytes();
ByteArray byteArray = new ByteArray(vm,b1);
arg_list.add(vm.addLocalObject(byteArray));

// bool类型
DvmBoolean boolobj = DvmBoolean.valueOf(vm, false);
arg_list.add(vm.addLocalObject(boolobj));

// Object类型
ArrayObject ArrayObj = new ArrayObject(0,1,null);
arg_list.add(vm.addLocalObject(ArrayObj));

// 非常规map类型
TreeMap<String,String> map = new TreeMap<>();
map.put("build","6180500");
map.put("mobi_app","android");
map.put("channel","shenma069");
map.put("appkey","1d8b6e7d45233436");
map.put("s_locale","zh_CH");
DvmObject mapObj = ProxyDvmObject.createObject(vm,map);

--------------------------------------
补充JNI形式要求
    基本数据类型直接传递
    字符串，字节数组基本对象类型
    	new StringObject(vm,string),new ByteArry(vm,byteArry)
    JDK标准库中， HashMap JSONObject
    	ProxyDvmObject.createObject(vm,map);
	非JDK标准库，Android Context ，SharePreference
        vm.resolveClass(vm,className).newObject(value)

```

### 2.补环境

```
参考      https://blog.csdn.net/qq_44628911/article/details/127322805
apk逆向教程    https://www.jianshu.com/u/01dab7278c9f
```

```java
switch (signature) {
case "android/os/Build->MODEL:Ljava/lang/String;": {
    return new StringObject(vm, "Pixel");
}
case "android/os/Build->MANUFACTURER:Ljava/lang/String;": {
    return new StringObject(vm, "Google");
}
case "android/os/Build$VERSION->SDK:Ljava/lang/String;": {
    return new StringObject(vm, "23");
}
case "android/app/ActivityThread->getSystemContext()Landroid/app/ContextImpl;": {
                return vm.resolveClass("android/app/ContextImpl").newObject(null);
            }
case "android/app/ContextImpl->getPackageManager()Landroid/content/pm/PackageManager;": {
                return vm.resolveClass("android/content/pm/PackageManager").newObject(null);
            }
case "android/app/ActivityThread->currentActivityThread()Landroid/app/ActivityThread;":{
                return vm.resolveClass("android/app/ActivityThread").newObject(null);
            }
case "com/yxcorp/gifshow/App->getPackageCodePath()Ljava/lang/String;":{
                return new StringObject(vm, "/data/app/com.smile.gifmaker-oyRnT1esU1Pf5iDY6JKtjA==/base.apk");
            }
case "com/yxcorp/gifshow/App->getAssets()Landroid/content/res/AssetManager;":{
                return new AssetManager(vm, signature);
            }  
case "com/yxcorp/gifshow/App->getPackageName()Ljava/lang/String;":{
                return new StringObject(vm, "com.smile.gifmaker");
            }  
case "com/kuaishou/android/security/internal/common/ExceptionProxy->nativeReport(ILjava/lang/String;)V":{
                return;
            }  
case "java/lang/Boolean->booleanValue()Z":{
                return false;
            }  
case "java/util/Map->get(Ljava/lang/Object;)Ljava/lang/Object;": {
                StringObject keyobject = varArg.getObjectArg(0);
                String key = keyobject.getValue();
                TreeMap<String, String> treeMap = (TreeMap<String, String>) dvmObject.getValue();
                String value = treeMap.get(key);
                return new StringObject(vm, value);
            }    
case "java/util/Map->isEmpty()Z": {
            TreeMap<String, String> treeMap = (TreeMap<String, String>)dvmObject.getValue();
            return treeMap.isEmpty();
        }

}
```



## 调用so

```java
public static void main(String[] args) {
        long start = System.currentTimeMillis();
        MainActivity mainActivity = new MainActivity();
        System.out.println("load offset=" + (System.currentTimeMillis() - start) + "ms");
        mainActivity.crack();
}

    private final AndroidEmulator emulator;
    private final VM vm;

    private final DvmClass dvmClass;

    private MainActivity() {
        //1.创建安卓模拟器实例
        emulator = AndroidEmulatorBuilder
            	//指定32位CPU
                .for32Bit()
            	//添加后端，推荐使用Dynarmic，运行速度快，但并不支持某些新特性
                .addBackendFactory(new DynarmicFactory(true))
            	//指定进程名，推荐以安卓包名
            	.serProcessName（"com.dta.unidbg"）
            	//设置根路径
            	.setRootDir(new File("target/rootfs/defulat"))
            	//生成AndroidEmulator实例
                .build();
        //2.获取操作内存接口
        Memory memory = emulator.getMemory();
        //3.设置Android SDK 版本
        LibraryResolver resolver = new AndroidResolver(23);
        memory.setLibraryResolver(resolver);
        //4.创建虚拟机
        vm = emulator.createDalvikVM();
        vm.setVerbose(true);
        //5.加载elf文件
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/armeabi-v7a/libnative-lib1.so"), false);
        //6.调用JNI_Onload
        dm.callJNI_OnLoad(emulator);
        //调用静态方法
        dvmClass = vm.resolveClass("com/roysue/easymd5/MainActivity");
        //调用非静态方法
        //dvmClass = vm.resolveClass("com/roysue/easymd5/MainActivity").newObject(null);
    }
//调用导出函数符号
    private void crack() {
        DvmObject result = dvmClass.callStaticJniMethodObject(emulator,"mdString(Ljava/lang/String;)Ljava/lang/String;","123456");

        System.out.println(result.getValue());

//        DvmObject<?> obj = ProxyDvmObject.createObject(vm, this);
//        DvmObject result1 = obj.callJniMethodObject(emulator,"mdString(Ljava/lang/String;)Ljava/lang/String;","123456");
//        System.out.println(result1.getValue());

    }
//调用函数地址
    private void callAddress(){
        //JNIEnv *env, jobject thiz, jstring data
        Pointer jniEnv = vm.getJNIEnv();
        DvmObject<?> object = ProxyDvmObject.createObject(vm, this);
        StringObject dta = new StringObject(vm,"123456");
        List<Object> list = new ArrayList<>();

        list.add(jniEnv);
        list.add(vm.addLocalObject(object));
        list.add(vm.addLocalObject(dta));

        Number number = module.callFunction(emulator, 0x8e7d, list.toArray());
        DvmObject<?> object1 = vm.getObject(number.intValue());
        System.out.println(object1.getValue());

    }
```

## emulator 的操作

```java
// 获取内存操作接口
Memory memory1 = emulator.getMemory();
 
// 获取进程id
int pid = emulator.getPid();
 
//创建虚拟机
VM dalvikVM = emulator.createDalvikVM();
 
//创建虚拟机并指定文件
VM dalvikVM1 = emulator.createDalvikVM(new File("ss/ss/apk"));
 
//获取已经创建的虚拟机
VM dalvikVM2 = emulator.getDalvikVM();
 
//显示当前寄存器的状态 可指定寄存器
emulator.showRegs();
 
// 获取后端CPU
Backend backend = emulator.getBackend();
 
//获取进程名
String processName = emulator.getProcessName();
 
// 获取寄存器
RegisterContext context = emulator.getContext();
 
//Trace 读取内存
emulator.traceRead(1,0);
 
// trace 写内存
emulator.traceWrite(1,0);
 
//trace 汇编
emulator.traceCode(1,0);
 
// 是否在运行
boolean running = emulator.isRunning();

// 写内存
    // 在r0寄存器放入指针类型
    emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_R0,memoryBlock.getPointer().peer);
    // 在r1寄存器写入int类型
    emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_R1, fakeLength);
```

## memory 操作

```java
// 指定安卓sdk  版本 只支持 19 和 23
memory.setLibraryResolver(new AndroidResolver(23));
 
// 拿到一个指针 指向内存地址 通过该指针可操作内存
UnidbgPointer pointer = memory.pointer(0x11111111);
 
//获取当前内存映射的情况
Collection<MemoryMap> memoryMap = memory1.getMemoryMap();
 
//根据模块名 来拿某个模块
Module sss = memory1.findModule("sss");
 
// 根据地址 来拿某个模块
Module moduleByAddress = memory1.findModuleByAddress(0x111111);
```

## VM 操作

```java
//推荐指定apk 文件 unidbg会自动做许多固定的操作
VM vvm = emulator.createDalvikVM(new File("ssss.apk"));
 
// 是否输出jni 运行日志
vvm.setVerbose(true);
 
//加载so模块 参数二设置是否自动调用init函数
DalvikModule dalvikModule = vvm.loadLibrary(new File("ss.so"), true);
 
// 设置jni 交互接口 参数需要实现jni接口 推荐使用this 继承AbstractJni
vvm.setJni(this);
 
//获取JNIEnv 指针 可以作为参数传递
Pointer jniEnv = vm.getJNIEnv();
 
//获取JavaVM 指针
Pointer javaVM = vm.getJavaVM();
 
//调用jni_onload函数
dalvikModule.callJNI_OnLoad(emulator);
vm.callJNI_OnLoad(emulator,dalvikModule.getModule());
```

## 符号调用

```java
// 创建一个vm 对象，相当于 java 层去调用native函数类的实例对象
// DvmObject obj = ProxyDvmObject.createObject(vm,this); // 默认获取MainActivity 当有很多类的时候，防止默认指定错误，可以以下指定
DvmObject<?> obj = vm.resolveClass("com/example/demo01/MainActivity").newObject(null);
 
String signSting = "123456";
 
DvmObject dvmObject = obj.callJniMethodObject(emulator, "jniMd52([B)Ljava/lang/String;", signSting.getBytes(StandardCharsets.UTF_8));
 
String result = (String) dvmObject.getValue();
 
System.out.println("[symble] Call the so md5 function result is ==> " + result);
```

## 地址调用

```java
ArrayList<Object> args = new ArrayList<>();
 
Pointer jniEnv = vm.getJNIEnv();
 
DvmObject object1 = ProxyDvmObject.createObject(vm, this);
 
// DvmObject<?> dvmObject = vm.resolveClass("com/xx/xx/MainActivity").newObject(null);
 
args.add(jniEnv);
 
// args.add(vm.addLocalObject(object1));// args.add(null)
 args.add(null);
 
args.add(vm.addLocalObject(new StringObject(vm, "123456")));
 
Number number = module.callFunction(emulator, 0x11AE8 + 1, args.toArray());// 是个地址
 
System.out.println("[addr] number is ==> " + number.intValue());
 
DvmObject<?> object = vm.getObject(number.intValue());
 
System.out.println("[addr] Call the so md5 function result is ==> " + object.getValue());
```

## Unicorn Hook

```java
emulator.getBackend().hook_add_new(new CodeHook() {
    @Override
    public void hook(Backend backend, long address, int size, Object user) {
        // 获取寄存器上下文
        RegisterContext context = emulator.getContext();
        //System.out.println(user);
        //System.out.println(size);
        if (address == module.base + 0x1FF4){
            Pointer md5Ctx = context.getPointerArg(0);
            Inspector.inspect(md5Ctx.getByteArray(0, 32), "md5Ctx");
            Pointer plainText = context.getPointerArg(1);
            int length = context.getIntArg(2);
            Inspector.inspect(plainText.getByteArray(0, length), "plainText");
        }else if (address == module.base + 0x2004){
            Pointer cipherText = context.getPointerArg(1);
            Inspector.inspect(cipherText.getByteArray(0, 16), "cipherText");
        }
 
    }
    @Override
    public void onAttach(UnHook unHook) {
    }
    @Override
    public void detach() {
    }
}, module.base + 0x1FE8, module.base + 0x2004, "xxxxzzzz");
```

## 打印调用栈

```java
public void callFunc() {
    emulator.getBackend().hook_add_new(new CodeHook() {
        @Override
        public void hook(Backend backend, long address, int size, Object user) {
 
            System.out.println("开始--------------------------");
            System.out.println(user);
            System.out.println(size);
            emulator.getUnwinder().unwind();
            System.out.println("===============================");
 
        }
 
        @Override
        public void onAttach(UnHook unHook) {
 
        }
 
        @Override
        public void detach() {
 
        }
    },module.base+0xAD40,module.base+0xAD40,"xibei");
 
 
}
```

## 监控内存读写

### 将信息输出到文件

```java
String traceFile = "myMonitorFile";
PrintStream traceStream = null;
try {
    traceStream = new PrintStream(new FileOutputStream(traceFile), true);
} catch (FileNotFoundException e) {
    e.printStackTrace();
}
```

### 监控内存读

```java
emulator.traceRead(module.base, module.base + module.size).setRedirect(traceStream);
```

### 监控内存写

```java
emulator.traceWrite(module.base, module.base + module.size).setRedirect(traceStream);
```

### 申请内存写入寄存器

```java
emulator.traceCode();
UnidbgPointer buffer = memory.malloc(32, false).getPointer();  //申请内存
buffer.setString(0, "f72c5a36569418a20907b55be5bf95ad");       //将字符串放到内存当中
Backend backend = emulator.getBackend();
backend.reg_write(ArmConst.UC_ARM_REG_R4, buffer.peer);  //将r4寄存器指向申请的字符串的地址
module.callFunction(emulator, 0x108B); //程序从这里开始执行  thumb指令要加1
```

## trace

```java
String traceFile = "myTraceCodeFile";
PrintStream traceStream = null;
try {
    traceStream = new PrintStream(new FileOutputStream(traceFile), true);
} catch (FileNotFoundException e) {
    e.printStackTrace();
}
emulator.traceCode(module.base, module.base + module.size).setRedirect(traceStream);
```



## 添加断点(27课)

```java
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import unicorn.ArmConst;
import java.io.File;

public class MainActivity {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Memory memory;
    private final Module module;

    public MainActivity() {
        //1.创建安卓模拟器实例
        emulator = AndroidEmulatorBuilder
            .for32Bit()
            //.setRootDir(new File("target/rootfs/default"))
            //.addBackendFactory(new DynarmicFactory(true))
            .build();
	    //2.获取操作内存接口
        memory = emulator.getMemory();
        //3.设置Android SDK 版本
        memory.setLibraryResolver(new AndroidResolver(23));
	   //4.创建虚拟机
        vm = emulator.createDalvikVM();      
        vm.setVerbose(true);
       //5.加载elf文件
        DalvikModule dalvikModule = vm.loadLibrary(new File("unidbg-android/src/test/java/com/unidbg_27/libcyberpeace.so"), false);
        module = dalvikModule.getModule();
		//6。调用JNI_Onload
        vm.callJNI_OnLoad(emulator, module);
    }
    public static void main(String[]args) {
        long start = System.currentTimeMillis();
        MainActivity mainActivity = new MainActivity();
        System.out.println("load the vm " + (System.currentTimeMillis() - start) + "ms");
        mainActivity.debugger();
        //mainActivity.check();
        mainActivity.callAddress();
    }

    private void debugger() {
        emulator.attach().addBreakPoint(module, 0x10b8);
    }

    private void check() {
        DvmClass obj = vm.resolveClass("com/testjava/jack/pingan2/cyberpeace");
        //public static native int CheckString(String str);
        String input = "123456654321abcdeffedcba4321abcd";
        int i = obj.callStaticJniMethodInt(emulator, "CheckString(Ljava/lang/String;)I", input);
        System.out.println("result  ==> " + i);
    }

    private void callAddress() {
        emulator.traceCode();
        UnidbgPointer buffer = memory.malloc(32, false).getPointer();  //申请内存
        buffer.setString(0, "f72c5a36569418a20907b55be5bf95ad");       //将字符串放到内存当中
        Backend backend = emulator.getBackend();
        backend.reg_write(ArmConst.UC_ARM_REG_R4, buffer.peer);  //将r4寄存器指向申请的字符串的地址
        module.callFunction(emulator, 0x108B); //程序从这里开始执行  thumb指令要加1
    }
}

```

## callAddress调用JNI方法(27课)

```java
 //1.调用函数地址 
	private void callAddress() {
        emulator.traceCode();
        UnidbgPointer buffer = memory.malloc(32, false).getPointer();  //申请内存
        buffer.setString(0, "f72c5a36569418a20907b55be5bf95ad");       //将字符串放到内存当中
        Backend backend = emulator.getBackend();
        backend.reg_write(ArmConst.UC_ARM_REG_R4, buffer.peer);  //将r4寄存器指向申请的字符串的地址
        module.callFunction(emulator, 0x108B); //程序从这里开始执行  thumb指令要加1
    }

//2.调用函数地址
    private void callAddress(){
        //JNIEnv *env, jobject thiz, jstring data
        Pointer jniEnv = vm.getJNIEnv();
        DvmObject<?> object = ProxyDvmObject.createObject(vm, this);
        StringObject dta = new StringObject(vm,"123456");
        List<Object> list = new ArrayList<>();

        list.add(jniEnv);
        list.add(vm.addLocalObject(object));
        list.add(vm.addLocalObject(dta));

        Number number = module.callFunction(emulator, 0x8e7d, list.toArray());
        DvmObject<?> object1 = vm.getObject(number.intValue());
        System.out.println(object1.getValue());

    }
```

## Hook(HookZz  23课)

```java
//对32位支持比较好
private void hookZz() {
    HookZz hookZz = HookZz.getInstance(emulator);
    
    // 相当于frida的attach
    // hook的函数也可这样获取   module.findSymbolByName("ss_encrypt")
    hookZz.wrap(module.base + 0x20ad, new WrapCallback<HookZzArm32RegisterContextImpl>() {
        @Override
        public void preCall(Emulator<?> emulator, HookZzArm32RegisterContextImpl ctx, HookEntryInfo info) {
            UnidbgPointer arg0 = ctx.getPointerArg(0);
            UnidbgPointer arg1 = ctx.getPointerArg(1);
            System.out.println("arg0->" + arg0.getString(0));
            System.out.println("arg1->" + arg1.getLong(0));

            Inspector.inspect(arg1.getByteArray(0,200),"arg1存储内容");  #打印内存
            ctx.push(arg1);
        }

        @Override
        public void postCall(Emulator<?> emulator, HookZzArm32RegisterContextImpl ctx, HookEntryInfo info) {
            UnidbgPointer arg1 = ctx.pop();
            Inspector.inspect(arg1.getByteArray(0,200),"arg1存储内容");  #打印内存
            super.postCall(emulator, ctx, info);
        }
    });
    
    // 相当于frida的replace
    hookZz.replace(module.base + 0x20ad, new ReplaceCallback() {
        @Override
        public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {

            return super.onCall(emulator, context, originFunction);
        }

        @Override
        public void postCall(Emulator<?> emulator, HookContext context) {
            super.postCall(emulator, context);
        }
    },true);

}
```

## hook(Dobby 23课)

```java
//对64位支持比较好
public void dobbyHook(){
        Dobby dobby = Dobby.getInstance(emulator);
        dobby.replace(module.base + 0x20ad, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                HookStatus ret = HookStatus.RET(emulator, originFunction);
                System.out.println(ret.toString());
                return super.onCall(emulator, originFunction);
            }

            @Override
            public void postCall(Emulator<?> emulator, HookContext context) {
                super.postCall(emulator, context);
            }
        },true);

}
```

## Xhook(23课)

```java
IxHook xHook = XHookImpl.getInstance(emulator); // 加载xHook，支持Import hook，
xHook.register("libttEncrypt.so", "strlen", new ReplaceCallback() { // hook libttEncrypt.so的导入函数strlen
    @Override
    public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
        Pointer pointer = context.getPointerArg(0);
        String str = pointer.getString(0);
        System.out.println("strlen=" + str);
        context.push(str);
        return HookStatus.RET(emulator, originFunction);
    }
    @Override
    public void postCall(Emulator<?> emulator, HookContext context) {
        System.out.println("strlen=" + context.pop() + ", ret=" + context.getIntArg(0));
    }
}, true);
xHook.register("libttEncrypt.so", "memmove", new ReplaceCallback() {
    @Override
    public HookStatus onCall(Emulator<?> emulator, long originFunction) {
        RegisterContext context = emulator.getContext();
        Pointer dest = context.getPointerArg(0);
        Pointer src = context.getPointerArg(1);
        int length = context.getIntArg(2);
        Inspector.inspect(src.getByteArray(0, length), "memmove dest=" + dest);
        return HookStatus.RET(emulator, originFunction);
    }
});
xHook.register("libttEncrypt.so", "memcpy", new ReplaceCallback() {
    @Override
    public HookStatus onCall(Emulator<?> emulator, long originFunction) {
        RegisterContext context = emulator.getContext();
        Pointer dest = context.getPointerArg(0);
        Pointer src = context.getPointerArg(1);
        int length = context.getIntArg(2);
        Inspector.inspect(src.getByteArray(0, length), "memcpy dest=" + dest);
        return HookStatus.RET(emulator, originFunction);
    }
});
xHook.refresh(); // 使Import hook生效

```



## Xhook native层函数（46课）

```C++
#include <jni.h>
#include <string>
#include "include/xhook.h"
#include "log.h"
#include <android/log.h>

using namespace std;
string (*old_say_hello)();

string say_hello(){
    string hello = "Hello from C++   ";
    return hello;
}

string new_say_hello(){
    string old = old_say_hello();
    string hello = "hook success!";
    return old.append(hello);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_roysue_lesson46_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {

    int ret_register = xhook_register(".*libnative-lib\\.so$","_Z9say_hellov", (void *)new_say_hello, (void **)&old_say_hello);
    if(ret_register){
        //error
        LOGD("hook say_hello error:%d", ret_register);
    } else{
        //success
        LOGD("hook say_hello success:%d", ret_register);
    }

    int ret_refresh = xhook_refresh(0);

    if(ret_refresh){
        //error
        LOGD("refresh say_hello error:%d", ret_refresh);
    } else{
        //success
        LOGD("refresh say_hello success:%d", ret_refresh);
    }
    std::string hello = say_hello();
    return env->NewStringUTF(hello.c_str());
}
```

### CMakeLists.txt

```txt
cmake_minimum_required(VERSION 3.10.2)

project("lesson46")
include_directories(include)
add_library(xhook SHARED IMPORTED)
set_target_properties(xhook PROPERTIES IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/libs/${ANDROID_ABI}/libxhook.so)

add_library( # Sets the name of the library.
             native-lib

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             native-lib.cpp )

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

target_link_libraries( # Specifies the target library.
                       native-lib
                        xhook
                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )
```

## xhook 寻找so文件基地址

### native-lib.cpp

```C++
#include <jni.h>
#include <string>
#include "include/xhook.h"
#include "log.h"
#include <android/log.h>
#include "util.h"

using namespace std;
string (*old_say_hello)();

string say_hello(){
    string hello = "Hello from C++   ";
    return hello;
}

string new_say_hello(){
    string old = old_say_hello();
    string hello = "hook success!";
    return old.append(hello);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_roysue_lesson46_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {

    int ret_register = xhook_register(".*libnative-lib\\.so$","_Z9say_hellov", (void *)new_say_hello, (void **)&old_say_hello);
    if(ret_register){
        //error
        LOGD("hook say_hello error:%d", ret_register);
    } else{
        //success
        LOGD("hook say_hello success:%d", ret_register);
    }

    int ret_refresh = xhook_refresh(0);

    if(ret_refresh){
        //error
        LOGD("refresh say_hello error:%d", ret_refresh);
    } else{
        //success
        LOGD("refresh say_hello success:%d", ret_refresh);
    }

    get_lib_info("libnative-lib.so");    //调用get_lib_info在logcat输出so相关的信息

    std::string hello = say_hello();
    return env->NewStringUTF(hello.c_str());
}
```

### util.h

```c++
//
// Created by root on 5/31/24.
//

#ifndef LESSON46_UTIL_H
#define LESSON46_UTIL_H
#include <link.h>

struct iterater_data{
    char *lib_name;
    dl_phdr_info **info;
};

int callback(struct dl_phdr_info *info,
             size_t size, void *data){

    struct iterater_data *data_ = (struct iterater_data *)data;
    if (strstr(info->dlpi_name, data_->lib_name) != nullptr){
        LOGD("%s:%lx", info->dlpi_name, info->dlpi_addr);
        *data_->info = info;
        return 1;
    }
    return 0;
}

dl_phdr_info *get_lib_info(char *lib_name){
    struct iterater_data data;
    data.lib_name = lib_name;
    data.info = (dl_phdr_info **)malloc(sizeof(data.info));
    *data.info = nullptr;

    int ret = dl_iterate_phdr(callback, (void *)&data);
    if (ret){
        //found
        LOGD("found aim elf %s:%lx", (*data.info)->dlpi_name, (*data.info)->dlpi_addr);
        dl_phdr_info *ret = *data.info;
        free(data.info);
        return ret;
    }
    return nullptr;
}

#endif //LESSON46_UTIL_H
```

## Unidbg与Unicorn集成Hook

```java
package com.dta.kanxuelesson5;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.*;
import com.github.unidbg.hook.xhook.IxHook;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.XHookImpl;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import unicorn.ArmConst;

import java.io.File;

public class HookDemo extends AbstractJni {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    private final Memory memory;

    public static void main(String[] args) {
        HookDemo hookDemo = new HookDemo();
//         hookDemo.debugger();
//         hookDemo.hook_addBreakPoint();
         hookDemo.hook_codehook();
        // hookDemo.replace_addBreakPoint();
        // hookDemo.replace_verify_sign();
        // hookDemo.replace_verify_sign_fixed();
        // hookDemo.patch();
        // hookDemo.xhookTest();
//        hookDemo.hookZzTest();
        hookDemo.call();
    }

    public HookDemo(){
            emulator = AndroidEmulatorBuilder
                .for32Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .build();

            memory = emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(23));
            vm = emulator.createDalvikVM(
                    new File("unidbg-android/src/test/java/com/dta/kanxuelesson5/test-debug.apk"));
            vm.setJni(this);
            vm.setVerbose(true);
            DalvikModule dm = vm.loadLibrary("test", true);
            module = dm.getModule();
            dm.callJNI_OnLoad(emulator);
    }

    public void call(){
        DvmClass MainActivity = vm.resolveClass("com.zapata.test.MainActivity");
        String methodSign = "hook_test()V";
        MainActivity.callStaticJniMethod(emulator, methodSign);
    }

    public void debugger(){
        emulator.attach().addBreakPoint(module.findSymbolByName("base64_encode").getAddress());
    }
	// 函数级Hook
    public void hook_addBreakPoint(){
        emulator.attach().addBreakPoint(module.findSymbolByName("base64_encode").getAddress(), new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                // 获取寄存器
                RegisterContext registerContext = emulator.getContext();
                UnidbgPointer arg0 = registerContext.getPointerArg(0);
//                System.out.println(arg0.getString(0));
                int len = registerContext.getIntArg(1);
                UnidbgPointer arg2 = registerContext.getPointerArg(2);
                // if(len == 6){
                //     Inspector.inspect(arg0.getByteArray(0,len),"base64 encode input");
                //     return false;
                // }
                // else{
                //     return true;
                // }

                Inspector.inspect(arg0.getByteArray(0,len),"base64 encode input");
                emulator.attach().addBreakPoint(registerContext.getLRPointer().peer, new BreakPointCallback() {
                    @Override
                    public boolean onHit(Emulator<?> emulator, long address) {
                        String result = arg2.getString(0);
                        System.out.println(result);
                        return true;
                    }
                });


                // 到达断点执行的操作： false => 停下来 ， true => 继续
                return true;
            }
        });
    }
	// 指令级Hook
    public void hook_codehook(){
        emulator.getBackend().hook_add_new(new CodeHook() {

            final RegisterContext registerContext = emulator.getContext();

            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if(address == module.base + 0x7EC){
                    int r0 = registerContext.getIntArg(ArmConst.UC_ARM_REG_R0);
                    System.out.println("0x7EC r0 => " + Integer.toHexString(r0));
                    // 获取调用栈
                    emulator.getUnwinder().unwind();
                }
                if(address == module.base + 0x7EE){
                    int r2 = registerContext.getIntArg(ArmConst.UC_ARM_REG_R2);
                    System.out.println("0x7EE r2 => " + Integer.toHexString(r2));
                }
                if(address == module.base + 0x7F0){
                    int r4 = registerContext.getIntArg(ArmConst.UC_ARM_REG_R4);
                    System.out.println("0x7F0 r4 => " + Integer.toHexString(r4));
                }
            }

            @Override
            public void onAttach(UnHook unHook) {

            }

            @Override
            public void detach() {

            }
        },module.base+0x7EC, module.size+0x800, null);
    }
	// 指令级替换寄存器中的值
    public void replace_addBreakPoint(){
        emulator.attach().addBreakPoint(module, 0x7EC, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                RegisterContext registerContext = emulator.getContext();
                UnidbgPointer input = registerContext.getPointerArg(0);
                UnidbgPointer output = registerContext.getPointerArg(2);
                int length = registerContext.getIntArg(1);
                String inputString = input.getString(0);
                String fakeName = "HelloWorld";
                int fakeLength = fakeName.length();
                MemoryBlock memoryBlock = memory.malloc(fakeLength,true);
                memoryBlock.getPointer().write(fakeName.getBytes());
                if(inputString.equals("r0ysue")){
                    emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_R0,memoryBlock.getPointer().peer);
                    emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_R1, fakeLength);
                }
                // onLeave
                emulator.attach().addBreakPoint(registerContext.getLRPointer().peer, new BreakPointCallback() {
                    @Override
                    public boolean onHit(Emulator<?> emulator, long address) {
                        String result = output.getString(0);
                        System.out.println("result => " +  result);
                        return true;
                    }
                });
                return true;
            }
        });
    }

    public void replace_verify_sign(){
        RegisterContext registerContext = emulator.getContext();
        emulator.attach().addBreakPoint(module.findSymbolByName("verifyApkSign").getAddress(),
                new BreakPointCallback() {
                    @Override
                    public boolean onHit(Emulator<?> emulator, long address) {
                        emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_PC, registerContext.getLRPointer().peer);
                        emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_R0,0);
                        return true;
                    }
                });
    }

    public void replace_verify_sign_fixed(){

        emulator.attach().addBreakPoint(module, 0x746,
                new BreakPointCallback() {
                    RegisterContext registerContext = emulator.getContext();
                    @Override
                    public boolean onHit(Emulator<?> emulator, long address) {
                        System.out.println("nop here ...");
                        emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_PC, registerContext.getLRPointer().peer+4+1);
                        emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_R0,0);
                        return true;
                    }
                });
    }

    public void patch(){
        emulator.getMemory().pointer(module.base + 0x746).setInt(0,0x4FF00000);
        // try(Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.ArmThumb)){
        //     KeystoneEncoded encoded = keystone.assemble("mov r0,0");
        //     byte[] patchCode = encoded.getMachineCode();
        //     System.out.println(patchCode);
        //     emulator.getMemory().pointer(module.base+0x746).write(0, patchCode, 0, patchCode.length);
        // }
    }
    public void xhookTest(){
        IxHook ixHook = XHookImpl.getInstance(emulator);
        ixHook.register(module.name, "base64_encode", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                String str = emulator.getContext().getPointerArg(0).getString(0);
                System.out.println("base64 input => " + str);
                return HookStatus.RET(emulator, originFunction);
            }
        });
        ixHook.refresh();
    }

    public void hookZzTest(){
        IHookZz hookZz = HookZz.getInstance(emulator);
        hookZz.wrap(module.findSymbolByName("base64_encode"), new WrapCallback<HookZzArm32RegisterContext>() {
            @Override
            public void preCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                Pointer pointer = ctx.getPointerArg(0);
                int length = ctx.getIntArg(1);
                byte[] input = pointer.getByteArray(0, length);
                Inspector.inspect(input, "base64 input");
                ctx.push(ctx.getPointerArg(2));
            }

            @Override
            public void postCall(Emulator<?> emulator, HookZzArm32RegisterContext ctx, HookEntryInfo info) {
                Pointer result = ctx.pop();
                System.out.println("result => " + result.getString(0));
            }
        });
    }

}

```

## Unidbg补环境(unidbg_31)

```java
public class MainActivity2 extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Memory memory;
    private final Module module;

    public MainActivity2(){
        emulator = AndroidEmulatorBuilder
                .for32Bit()
                //.setRootDir(new File("target/rootfs/default"))
                //.addBackendFactory(new DynarmicFactory(true))
                .build();

        memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        vm = emulator.createDalvikVM();
        vm.setVerbose(true);
        vm.setJni(this);

        DalvikModule dalvikModule = vm.loadLibrary(new File("unidbg-android/src/test/java/com/dta/lesson31/libcheck.so"), false);
        module = dalvikModule.getModule();

        vm.callJNI_OnLoad(emulator,module);
    }

    static {
        Logger.getLogger(AndroidElfLoader.class).setLevel(Level.INFO);
    }


    public static void main(String[] args) {
        long start = System.currentTimeMillis();
        MainActivity2 mainActivity = new MainActivity2();
        System.out.println("load the vm "+( System.currentTimeMillis() - start )+ "ms");
        mainActivity.sub_85E0();
    }

    private void sub_85E0() {
        //emulator.traceCode();
        List<Object> args = new ArrayList<>();
        UnidbgPointer ptr_arg0 = UnidbgPointer.pointer(emulator, module.base + 0xF1B0);
        args.add(ptr_arg0.toIntPeer());
        args.add(622);

        MemoryBlock malloc = memory.malloc(32, true);
        UnidbgPointer ptr_md5 = malloc.getPointer();
        String md5 = "f8c49056e4ccf9a11e090eaf471f418d";
        ptr_md5.write(md5.getBytes(StandardCharsets.UTF_8));
        args.add(ptr_md5.toIntPeer());

        Number[] numbers = module.callFunction(emulator, 0x85E1, args.toArray());
        System.out.println("result => " + numbers[0].longValue());

        sub_shellCode(numbers[0].longValue());
    }

    private void sub_shellCode(long addr) {
        List<Object> args = new ArrayList<>();

        String input = "qqqqqqq";
        MemoryBlock malloc = memory.malloc(input.length(), true);
        UnidbgPointer ptr_input = malloc.getPointer();

        UnidbgPointer ptr_v9 = memory.allocateStack(8);
        ptr_v9.setPointer(0,ptr_input);


        UnidbgPointer ptr_pipe = memory.allocateStack(8);
        ptr_pipe.setInt(0,0);
        ptr_pipe.setInt(4,1);

        ptr_v9.setPointer(4,ptr_pipe);

        args.add(ptr_v9.toIntPeer());
        Number[] numbers = module.callFunction(emulator, addr - module.base + 1, args.toArray());
        System.out.println("shellcode result => " + numbers[0].longValue());
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if(signature.equals("com/a/sample/loopcrypto/Decode->a([BI)Ljava/lang/String;")){
            byte[] bytes = (byte[]) varArg.getObjectArg(0).getValue();
            int i = varArg.getIntArg(1);
            String a = Encrypt.a(bytes, i);
            return new StringObject(vm, a);
        }
        return super.callStaticObjectMethod(vm, dvmClass, signature, varArg);
    }
}
```

## Unidbg补环境(unidbg_32)

```java
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.AndroidElfLoader;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import com.unidbg_31.Decode;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;


public class MainActivity extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Memory memory;
    private final Module module;

    public MainActivity(){
        emulator = AndroidEmulatorBuilder
                .for32Bit()
                //.setRootDir(new File("target/rootfs/default"))
                //.addBackendFactory(new DynarmicFactory(true))
                .build();

        memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/java/com/unidbg_32/app-debug.apk"));
        vm.setVerbose(true);
        vm.setJni(this);

        DalvikModule dalvikModule = vm.loadLibrary(new File("unidbg-android/src/test/java/com/unidbg_32/libdogpro.so"), false);
        module = dalvikModule.getModule();

        vm.callJNI_OnLoad(emulator,module);
    }

    static {
        Logger.getLogger(AndroidElfLoader.class).setLevel(Level.INFO);
    }
    public static void main(String[] args) {
        long start = System.currentTimeMillis();
        MainActivity mainActivity = new MainActivity();
        System.out.println("load the vm "+( System.currentTimeMillis() - start )+ "ms");
        mainActivity.getHash();
    }

    private void getHash() {
        DvmObject<?> dvmObject = vm.resolveClass("com/example/dogpro/MainActivity").newObject(null);
        String input = "/data/app/com.example.dogpro-pnF2J3-qBi8ei74vXTNXmQ==/base.apk";
        DvmObject<?> result = dvmObject.callJniMethodObject(emulator, "getHash(Ljava/lang/String;)Ljava/lang/String;", input);
        System.out.println("result ==>"+ result);
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (signature.equals("java/util/zip/ZipFile-><init>(Ljava/lang/String;)V")){
            String name = (String) vaList.getObjectArg(0).getValue();
            try {
                if (name.equals("/data/app/com.example.dogpro-pnF2J3-qBi8ei74vXTNXmQ==/base.apk")){
                    ZipFile zipFile = new ZipFile("unidbg-android/src/test/java/com/unidbg_32/app-debug.apk");
                    return vm.resolveClass("java/util/zip/ZipFile").newObject(zipFile);
                }
                return null;
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
        }
        return super.newObjectV(vm, dvmClass, signature, vaList);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (signature.equals("java/util/zip/ZipFile->entries()Ljava/util/Enumeration;")){
            ZipFile zipFile = (ZipFile) dvmObject.getValue();
            java.util.Enumeration<? extends ZipEntry> entries = zipFile.entries();
            DvmClass ZipEntryClass = vm.resolveClass("java/util/zip/ZipEntry");
            List<DvmObject<?>> objs = new ArrayList<>();
            while (entries.hasMoreElements()){
                ZipEntry zipEntry = entries.nextElement();
                objs.add(ZipEntryClass.newObject(zipEntry));
            }
            return new com.github.unidbg.linux.android.dvm.Enumeration(vm,objs);
        }
        if (signature.equals("java/util/zip/ZipEntry->getName()Ljava/lang/String;")){
            ZipEntry zipEntry = (ZipEntry) dvmObject.getValue();
            String name = zipEntry.getName();
            return new  StringObject(vm,name);
        }
        if (signature.equals("java/lang/String->toLowerCase()Ljava/lang/String;")){
            String s = (String) dvmObject.getValue();
            String s1 = s.toLowerCase();
            return new StringObject(vm,s1);
        }
        if (signature.equals("java/util/zip/ZipFile->getInputStream(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;")){
            ZipFile zipFile = (ZipFile) dvmObject.getValue();
            ZipEntry zipEntry = (ZipEntry) vaList.getObjectArg(0).getValue();
            try {
                InputStream inputStream = zipFile.getInputStream(zipEntry);
                return vm.resolveClass("java/io/InputStream").newObject(inputStream);
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
        }
        if (signature.equals("java/security/MessageDigest->digest()[B")){
            MessageDigest md = (MessageDigest) dvmObject.getValue();
            byte[] digest = md.digest();
            return new ByteArray(vm, digest);
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (signature.equals("java/lang/String->endsWith(Ljava/lang/String;)Z")){
            String value = (String) dvmObject.getValue();
            String suffix = (String) vaList.getObjectArg(0).getValue();
            return value.endsWith(suffix);
        }
        return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (signature.equals("java/io/InputStream->read([B)I")){
            InputStream inputStream = (InputStream) dvmObject.getValue();
            byte[] bytes = (byte[]) vaList.getObjectArg(0).getValue();
            try {
                int read = inputStream.read(bytes);
                return read;
            } catch (IOException e) {
                e.printStackTrace();
                return -1;
            }
        }
        return super.callIntMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (signature.equals("java/security/MessageDigest->update([B)V")){
            MessageDigest md = (MessageDigest) dvmObject.getValue();
            byte[] bytes = (byte[]) vaList.getObjectArg(0).getValue();
            md.update(bytes);
            return;
        }
        super.callVoidMethodV(vm, dvmObject, signature, vaList);
    }
}
```

## 猿人学第11题(补环境)

```java
package com.dta.yuanrenxue8;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.wrapper.DvmLong;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.io.IOException;

import java.util.Random;

public class MainActivity2 {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final DvmClass TTEncryptUtils;
    private final boolean logging;

    MainActivity2(boolean logging) {
        this.logging = logging;

        emulator = AndroidEmulatorBuilder.for32Bit().setProcessName("com.yuanrenxue.onlinejudge2020").build(); // 创建模拟器实例，要模拟32位或者64位，在这里区分
        final Memory memory = emulator.getMemory(); // 模拟器的内存操作接口
        memory.setLibraryResolver(new AndroidResolver(23)); // 设置系统类库解析

        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/java/com/dta/yuanrenxue8/YuanRenXueOJ_1.2-release.apk")); // 创建Android虚拟机
        vm.setVerbose(logging); // 设置是否打印Jni调用细节

        vm.setJni(new AbstractJni() {
            @Override
            public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
                if ("android/os/Looper->myLooper()Landroid/os/Looper;".equals(dvmMethod.toString())){
                    return vm.resolveClass("android/os/Looper").newObject(null);
                }
                return null;
            }
            @Override
            public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VaList vaList) {
                if ("java/util/Random-><init>()V".equals(dvmMethod.toString())){
                    return vm.resolveClass("java/util/Random").newObject(new Random());
                }else if("java/util/Random-><init>(J)V".equals(dvmMethod.toString())){
                    return vm.resolveClass("java/util/Random").newObject(new Random(vaList.getLongArg(0)));
                }
                return null;
            }
            @Override
            public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
                if ("java/util/Random->nextInt(I)I".equals(dvmMethod.toString())){
                    Random a = (Random)dvmObject.getValue();
                    return a.nextInt(vaList.getIntArg(0));
                }
                return 0;
            }
            @Override
            public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, DvmMethod dvmMethod, VaList vaList) {
                if("android/content/ContextWrapper->getFilesDir()Ljava/io/File;".equals(dvmMethod.toString())){
                    return vm.resolveClass("java/io/File").newObject(new File("/"));
                }else if("java/io/File->getAbsolutePath()Ljava/lang/String;".equals(dvmMethod.toString())){
                    return new StringObject(vm, "/");
                    // 这里会在你的电脑C:\Users\用户名称\AppData\Local\Temp\rootfs\default目录下创建一个.did.bin的文件
                }
                return null;
            }
            @Override
            public boolean acceptMethod(DvmClass dvmClass, String signature, boolean isStatic) {
                return true;
            }
        });

        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/armeabi-v7a/libyuanrenxue_native.so"), false); // 加载libttEncrypt.so到unicorn虚拟内存，加载成功以后会默认调用init_array等函数

        DvmClass cContextWrapper = vm.resolveClass("android/content/ContextWrapper");
        TTEncryptUtils = vm.resolveClass("com/yuanrenxue/onlinejudge2020/OnlineJudgeApp", cContextWrapper);

        dm.callJNI_OnLoad(emulator); // 手动执行JNI_OnLoad函数
        module = dm.getModule(); // 加载好的libttEncrypt.so对应为一个模块

    }

    void destroy() throws IOException {
        emulator.close();
        if (logging) {
            System.out.println("destroy");
        }
    }

    public static void main(String[] args) throws Exception {
        MainActivity2 test = new MainActivity2(false);
       // test.ttEncrypt(args[0]);
        test.ttEncrypt("1");
        test.destroy();
    }

    void ttEncrypt(String number){
        StringObject signobj = TTEncryptUtils.newObject(null).callJniMethodObject(emulator, "getSign(J)Ljava/lang/String;", DvmLong.valueOf(vm, Long.parseLong(number))); // 执行Jni方法
        String sign = signobj.getValue();
        System.out.println(sign);
    }
}
```



# Unicorn

## pom文件

```xml
<dependency>
    <groupId>com.github.zhkl0228</groupId>
    <artifactId>unicorn</artifactId>
    <version>1.0.12</version>
</dependency>
<dependency>
    <groupId>com.github.zhkl0228</groupId>
    <artifactId>capstone</artifactId>
    <version>3.0.11</version>
</dependency>
<dependency>
    <groupId>com.github.zhkl0228</groupId>
    <artifactId>keystone</artifactId>
    <version>0.9.5</version>
</dependency>
<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-log4j12</artifactId>
    <version>1.7.26</version>
    <scope>compile</scope>
</dependency>
```

## Unicorn的使用

```java
package com.mxy;

import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornConst;

public class Unicorn_ {
    static long BASE = 0x1000;
    public static void main(String[] args) {

        byte[] code = new byte[]{0x01,0x20,
                0x02,0x21,
                0x08,0x44};

        Unicorn unicorn = new Unicorn(UnicornConst.UC_ARCH_ARM,UnicornConst.UC_MODE_THUMB);//创建Unicorn对象

        unicorn.mem_map(BASE,0x1000,UnicornConst.UC_PROT_WRITE | UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);  //映射内存

        unicorn.mem_write(BASE,code);  //将code写入内存
        unicorn.emu_start(BASE+1,BASE+code.length,0,0);  //执行模拟器

        Long o = (Long) unicorn.reg_read(ArmConst.UC_ARM_REG_R0);  //读取R0寄存器的值
        System.out.println("result ==>"+o.intValue());
    }
}
```

## Unicorn的hook操作

```java
unicorn.hook_add(new BlockHook() {
    @Override
    public void hook(Unicorn unicorn, long l, int i, Object o) {
        System.out.println("BlockHooked--->");
    }
},BASE,BASE+code.length,null);

unicorn.hook_add(new CodeHook() {
    @Override
    public void hook(Unicorn unicorn, long l, int i, Object o) {
        System.out.println("CodeHooked--->");
    }
},BASE,BASE+code.length,null);
unicorn.hook_add(new ReadHook() {
    @Override
    public void hook(Unicorn unicorn, long l, int i, Object o) {
        System.out.println("ReadHooked--->");
    }
},BASE+0x100,BASE+102,null);
unicorn.hook_add(new WriteHook() {
    @Override
    public void hook(Unicorn unicorn, long l, int i, long l1, Object o) {
        System.out.println(String.format(">>> Memory write at 0x%x, block size = 0x%x, value is = 0x%x", l, i,l1));
    }
},BASE+0x100,BASE+0x102,null);
```

## KeyStone(将汇编转换成机器码)

```java
Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.ArmThumb);
String assembly =
                "movs r0, #3\n" +
                "movs r1, #2\n" +
                "add r0,r1\n" +
                "movs r2, #0x1100\n" +
                "str r0, [r2, #0]\n" +
                "ldr r3, [r2, #0]";
byte[] code = keystone.assemble(assembly).getMachineCode(); //将汇编转换成机器码
        
```

## Capstone(将机器码转换成汇编)

```java
Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.ArmThumb);
String assembly =
    "movs r0, #3\n" +
    "movs r1, #2\n" +
    "add r0,r1\n" +
    "movs r2, #0x1100\n" +
    "str r0, [r2, #0]\n" +
    "ldr r3, [r2, #0]";
byte[] code = keystone.assemble(assembly).getMachineCode(); //将汇编转换成机器码
Capstone cs = new Capstone(Capstone.CS_ARCH_ARM,Capstone.CS_MODE_THUMB);
Capstone.CsInsn[] disasm = cs.disasm(code, 0x1000);
for (Capstone.CsInsn i : disasm){
    System.out.println(String.format("0x%x:%s %s",i.address,i.mnemonic,i.opStr));
}
```

## Unicorn综合使用

```java
package com.mxy;

import capstone.Capstone;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneMode;
import unicorn.*;

import static unicorn.UnicornConst.UC_ERR_READ_UNMAPPED;
import static unicorn.UnicornConst.UC_HOOK_MEM_READ_UNMAPPED;

public class Unicorn_ {
    static long BASE = 0x1000;
    public static void main(String[] args) {

        Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.ArmThumb);

        String assembly = "" +
                "movs r0,#1\n" +
                "movs r1,#2\n" +
                "add r0,r1\n" +
                "movs r2, #0x1100\n" +
                "str r0, [r2,#0]\n" +
                "ldr r3,[r2,#0]";
        byte[] code = keystone.assemble(assembly).getMachineCode();

        Capstone cs = new Capstone(Capstone.CS_ARCH_ARM,Capstone.CS_MODE_THUMB);
        Capstone.CsInsn[] disasm = cs.disasm(code, 0x1000);
        for (Capstone.CsInsn i : disasm){
            System.out.println(String.format("0x%x:%s %s",i.address,i.mnemonic,i.opStr));
        }

//        byte[] code = new byte[]{0x01,0x20,
//                0x02,0x21,
//                0x08,0x44};

        Unicorn unicorn = new Unicorn(UnicornConst.UC_ARCH_ARM,UnicornConst.UC_MODE_THUMB);

        unicorn.mem_map(BASE,0x1000,UnicornConst.UC_PROT_WRITE | UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);

        unicorn.mem_write(BASE,code);

        unicorn.hook_add(new BlockHook() {
            @Override
            public void hook(Unicorn unicorn, long l, int i, Object o) {
                System.out.println("BlockHooked--->");
            }
        },BASE,BASE+code.length,null);

        unicorn.hook_add(new CodeHook() {
            @Override
            public void hook(Unicorn unicorn, long l, int i, Object o) {
                System.out.println("CodeHooked--->");
            }
        },BASE,BASE+code.length,null);
        unicorn.hook_add(new ReadHook() {
            @Override
            public void hook(Unicorn unicorn, long l, int i, Object o) {
                System.out.println("ReadHooked--->");
            }
        },BASE+0x100,BASE+102,null);
        unicorn.hook_add(new WriteHook() {
            @Override
            public void hook(Unicorn unicorn, long l, int i, long l1, Object o) {
                System.out.println(String.format(">>> Memory write at 0x%x, block size = 0x%x, value is = 0x%x", l, i,l1));
            }
        },BASE+0x100,BASE+0x102,null);

        unicorn.emu_start(BASE+1,BASE+code.length,0,0);

        Long o = (Long) unicorn.reg_read(ArmConst.UC_ARM_REG_R0);
        System.out.println("result ==>"+o.intValue());
    }
}

```



# SpringBoot2

尚硅谷笔记 https://www.yuque.com/atguigu/springboot

中文文档 http://felord.cn/_doc/_springboot/2.1.5.RELEASE/_book/

英文文档 https://docs.spring.io/spring-boot/docs/current/reference/html/index.html

https://spring.io/projects/spring-boot

## 一.创建Maven

### 1.1引入依赖

```xml
	<parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.3.4.RELEASE</version>
    </parent>


    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

    </dependencies>
```

### 1.2创建主程序

```java
/**
 * 主程序类
 * @SpringBootApplication：这是一个SpringBoot应用
 */
@SpringBootApplication
public class MainApplication {

    public static void main(String[] args) {
        SpringApplication.run(MainApplication.class,args);
    }
}
```

### 1.3编写业务

```java
@RestController
public class HelloController {


    @RequestMapping("/hello")
    public String handle01(){
        return "Hello, Spring Boot 2!";
    }


}
```

### 1.4简化配置

applicatioan.properties

```xml
server.port=8888
```

### 1.5简化部署

```xml
 <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
```

## 二.了解自动配置原理 

### 2.1依赖管理 

```xml
依赖管理    
<parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.3.4.RELEASE</version>
</parent>

他的父项目
 <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-dependencies</artifactId>
    <version>2.3.4.RELEASE</version>
  </parent>

几乎声明了所有开发中常用的依赖的版本号,自动版本仲裁机制

```

- 开发导入starter场景启动器

  ```xml
  1、见到很多 spring-boot-starter-* ： *就某种场景
  2、只要引入starter，这个场景的所有常规需要的依赖我们都自动引入
  3、SpringBoot所有支持的场景
  https://docs.spring.io/spring-boot/docs/current/reference/html/using-spring-boot.html#using-boot-starter
  4、见到的  *-spring-boot-starter： 第三方为我们提供的简化开发的场景启动器。
  5、所有场景启动器最底层的依赖
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter</artifactId>
    <version>2.3.4.RELEASE</version>
    <scope>compile</scope>
  </dependency>
  ```

- 可以修改默认版本号

  ```xml
  1、查看spring-boot-dependencies里面规定当前依赖的版本 用的 key。
  2、在当前项目里面重写配置
      <properties>
          <mysql.version>5.1.43</mysql.version>
      </properties>
  ```

### 2.2自动配置

- 默认的包结构

- - 主程序所在包及其下面的所有子包里面的组件都会被默认扫描进来
  - 无需以前的包扫描配置

- - 想要改变扫描路径，@SpringBootApplication(scanBasePackages=**"com.atguigu"**)

- - - 或者@ComponentScan 指定扫描路径

```java
@SpringBootApplication
等同于
@SpringBootConfiguration
@EnableAutoConfiguration
@ComponentScan("com.atguigu.boot")
```

### 2.3容器功能

#### 2.3.1组件添加

###### 	1、@Configuration

- 基本使用
- **Full模式与Lite模式**

- - 示例
  - 最佳实战

- - - 配置 类组件之间无依赖关系用Lite模式加速容器启动过程，减少判断
    - 配置类组件之间有依赖关系，方法会被调用得到之前单实例组件，用Full模式

```java
#############################Configuration使用示例######################################################
/**
 * 1、配置类里面使用@Bean标注在方法上给容器注册组件，默认也是单实例的
 * 2、配置类本身也是组件
 * 3、proxyBeanMethods：代理bean的方法
 *      Full(proxyBeanMethods = true)、【保证每个@Bean方法被调用多少次返回的组件都是单实例的】
 *      Lite(proxyBeanMethods = false)【每个@Bean方法被调用多少次返回的组件都是新创建的】
 *      组件依赖必须使用Full模式默认。其他默认是否Lite模式
 *
 *
 *
 */
@Configuration(proxyBeanMethods = false) //告诉SpringBoot这是一个配置类 == 配置文件
public class MyConfig {

    /**
     * Full:外部无论对配置类中的这个组件注册方法调用多少次获取的都是之前注册容器中的单实例对象
     * @return
     */
    @Bean //给容器中添加组件。以方法名作为组件的id。返回类型就是组件类型。返回的值，就是组件在容器中的实例
    public User user01(){
        User zhangsan = new User("zhangsan", 18);
        //user组件依赖了Pet组件
        zhangsan.setPet(tomcatPet());
        return zhangsan;
    }

    @Bean("tom")
    public Pet tomcatPet(){
        return new Pet("tomcat");
    }
}


################################@Configuration测试代码如下########################################
@SpringBootConfiguration
@EnableAutoConfiguration
@ComponentScan("com.atguigu.boot")
public class MainApplication {

    public static void main(String[] args) {
        //1、返回我们IOC容器
        ConfigurableApplicationContext run = SpringApplication.run(MainApplication.class, args);

        //2、查看容器里面的组件
        String[] names = run.getBeanDefinitionNames();
        for (String name : names) {
            System.out.println(name);
        }

        //3、从容器中获取组件

        Pet tom01 = run.getBean("tom", Pet.class);

        Pet tom02 = run.getBean("tom", Pet.class);

        System.out.println("组件："+(tom01 == tom02));


        //4、com.atguigu.boot.config.MyConfig$$EnhancerBySpringCGLIB$$51f1e1ca@1654a892
        MyConfig bean = run.getBean(MyConfig.class);
        System.out.println(bean);

        //如果@Configuration(proxyBeanMethods = true)代理对象调用方法。SpringBoot总会检查这个组件是否在容器中有。
        //保持组件单实例
        User user = bean.user01();
        User user1 = bean.user01();
        System.out.println(user == user1);


        User user01 = run.getBean("user01", User.class);
        Pet tom = run.getBean("tom", Pet.class);

        System.out.println("用户的宠物："+(user01.getPet() == tom));



    }
}
```

###### 2、@Bean、@Component、@Controller、@Service、@Repository

###### 3、@ComponentScan、@Import

```java
 * 4、@Import({User.class, DBHelper.class})
 *      给容器中自动创建出这两个类型的组件、默认组件的名字就是全类名
 *
 *
 *
 */

@Import({User.class, DBHelper.class})
@Configuration(proxyBeanMethods = false) //告诉SpringBoot这是一个配置类 == 配置文件
public class MyConfig {
}
```

###### 4、@Conditional

条件装配：满足Conditional指定的条件，则进行组件注入

```java
=====================测试条件装配==========================
@Configuration(proxyBeanMethods = false) //告诉SpringBoot这是一个配置类 == 配置文件
//@ConditionalOnBean(name = "tom")
@ConditionalOnMissingBean(name = "tom")
public class MyConfig {


    /**
     * Full:外部无论对配置类中的这个组件注册方法调用多少次获取的都是之前注册容器中的单实例对象
     * @return
     */

    @Bean //给容器中添加组件。以方法名作为组件的id。返回类型就是组件类型。返回的值，就是组件在容器中的实例
    public User user01(){
        User zhangsan = new User("zhangsan", 18);
        //user组件依赖了Pet组件
        zhangsan.setPet(tomcatPet());
        return zhangsan;
    }

    @Bean("tom22")
    public Pet tomcatPet(){
        return new Pet("tomcat");
    }
}

public static void main(String[] args) {
        //1、返回我们IOC容器
        ConfigurableApplicationContext run = SpringApplication.run(MainApplication.class, args);

        //2、查看容器里面的组件
        String[] names = run.getBeanDefinitionNames();
        for (String name : names) {
            System.out.println(name);
        }

        boolean tom = run.containsBean("tom");
        System.out.println("容器中Tom组件："+tom);

        boolean user01 = run.containsBean("user01");
        System.out.println("容器中user01组件："+user01);

        boolean tom22 = run.containsBean("tom22");
        System.out.println("容器中tom22组件："+tom22);


    }
```

#### 2.3.2原生配置文件引入 

###### 1、@ImportResource

```xml
======================beans.xml=========================
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:context="http://www.springframework.org/schema/context"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd http://www.springframework.org/schema/context https://www.springframework.org/schema/context/spring-context.xsd">

    <bean id="haha" class="com.atguigu.boot.bean.User">
        <property name="name" value="zhangsan"></property>
        <property name="age" value="18"></property>
    </bean>

    <bean id="hehe" class="com.atguigu.boot.bean.Pet">
        <property name="name" value="tomcat"></property>
    </bean>
</beans>
```

```java
@ImportResource("classpath:beans.xml")
public class MyConfig {}

======================测试=================
        boolean haha = run.containsBean("haha");
        boolean hehe = run.containsBean("hehe");
        System.out.println("haha："+haha);//true
        System.out.println("hehe："+hehe);//true
```

#### 2.3.3配置绑定 

###### 1、@ConfigurationProperties

```java
/**
 * 只有在容器中的组件，才会拥有SpringBoot提供的强大功能
 */
@Component
@ConfigurationProperties(prefix = "mycar")
public class Car {

    private String brand;
    private Integer price;

    public String getBrand() {
        return brand;
    }

    public void setBrand(String brand) {
        this.brand = brand;
    }

    public Integer getPrice() {
        return price;
    }

    public void setPrice(Integer price) {
        this.price = price;
    }

    @Override
    public String toString() {
        return "Car{" +
                "brand='" + brand + '\'' +
                ", price=" + price +
                '}';
    }
}
```

###### 2、@Component + @ConfigurationProperties

```java
@EnableConfigurationProperties(Car.class)
//1、开启Car配置绑定功能
//2、把这个Car这个组件自动注册到容器中
public class MyConfig {
}
```



# ---------------------------------------------

# xposed框架

```
创建安卓工程 --> 新增lib目录 --> api-82.jar拖入后构建路径(实际上就是使用第三方jar包) --> 修改AndroidManifest.xml

    <application
        android:allowBackup="true"
        android:icon="@drawable/ic_launcher"
        android:label="@string/app_name" >
        <meta-data
            android:name="xposedmodule"
            android:value="true" />
        <meta-data
            android:name="xposeddescription"
            android:value="my name is xiaojianbang" />
        <meta-data
            android:name="xposedminversion"
            android:value="53" />
    </application>

src --> 新建一个包com.xposed --> 新建一个类

package com.xposed;

import android.util.Log;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class Hook implements IXposedHookLoadPackage {
	public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
		
		Log.d("xiaojianbang", "hook...");
		
		if (!lpparam.packageName.equals("com.xingin.xhs")) return;
		
		Log.d("xiaojianbang", "hooking...");
	}
}
在assets目录下创建xposed_init文件写入Hook类的路径
assets --> xposed_init --> com.xposed.Hook

安装xposed框架 --> 给予root权限 重启
安装自写的模块 --> 勾选 --> 框架 重启
```

## 主体框架

```java
public class HookTest implements IXposedHookLoadPackage {
    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
        XposedBridge.log("Loaded app: " + lpparam.packageName);
        // 找到该类
        final Class clazz = XposedHelpers.findClass("com.baoming",lpparam.classLoader);
```



## Hook静态变量

```java
// 1----hook静态变量
if(lpparam.packageName.equals("com.baoming")){
    XposedHelpers.setStaticIntField(clazz,"",0);
    XposedHelpers.setStaticObjectField(clazz,"","");
}
```

## Hook普通方法

```java
 // 2----hook普通方法：也可以使用xposedBridge.hookALLMethods()
 if (lpparam.packageName.equals("com.baoming")){
     // findAndHookMethod()方法中的第一个参数是，你要hook的方法所属的类
     // findAndHookMethod()方法中的第二个参数是，你要hook的方法
     // findAndHookMethod()方法中的第三个参数是，“public_method_name”的参数
     // findAndHookMethod()方法中的第四个参数是，回调方法（可以再里面修改参数返回值或者添加逻辑）
     XposedHelpers.findAndHookMethod(clazz, "public_method_name", String.class, new XC_MethodHook() {
     // findAndHookMethod（）有两种形式，参数不同而已 可点击ctrl进去查看，一看便知
     // beforeHookedMethod(MethodHookParam param) 中的param表示参数列表
     @Override
     protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
     // param.args表示原参数的参数列表
     Log.d("普通方法","" + param.args[0]);
     super.beforeHookedMethod(param);
     }

    @Override
    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
    // 获取返回值 param.getresult()
    super.beforeHookedMethod(param);
    Log.d("普通方法","" + param.getResult());
    }
    });
}

```

## Hook无参构造方法

```java
// 3 ----hook无参构造方法,也可以使用xposedBridge.hookAllConstructors()
if (lpparam.packageName.equals("com.baoming")){
    XposedHelpers.findAndHookConstructor(clazz, new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            super.beforeHookedMethod(param);
            Log.d("构造函数","hook无参构造方法前");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            super.beforeHookedMethod(param);
            Log.d("构造函数","hook无参构造方法后");
        }
    });
}
```

## Hook有参构造方法

```java
// 4----hook有参构造方法
if (lpparam.packageName.equals("com.baoming")){
    XposedHelpers.findAndHookConstructor(clazz, String.class,new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            super.beforeHookedMethod(param);
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            super.beforeHookedMethod(param);
        }
    });
}
```

## Hook复杂参数，类似map

```java
// 5 ----hook的方法中参数比较复杂：类似与Map,ArrayList等参数的表示方法
// public void public_method_name(String str,String[][] strarr,Map<String string> map,ArrayList arrlist)
if (lpparam.packageName.equals("com.baoming")){
	XposedHelpers.findAndHookMethod(clazz, "public_method_name",
	"java.lang.String", // 也可以使用String.class
	"[[Ljava.lang.String;", // String[][].class，同理当参数类型为String[]时,也可以写成“[java.lang.String”
	Map.class,
	Class.forName("java.util.ArrayList"), // ArrayList.class
	new XC_MethodHook() {
	@Override
		protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
		super.beforeHookedMethod(param);
		}
	}
    );
}
```

## Hook自定义类型参数

```java
// 6 --- 自定义类型参数：
//说白了所有的参数类型都是字节码，指要能获取参数类型的字节码就可以，有两种方式
// 自定义一个类public class Demo{}   这个类作为一个参数的类型：public void methodName(Demo demo){}
if (lpparam.packageName.equals("com.baoming")){
    // 也可以反射获取字节码 两种方式自行选择 clazz1 = Class.forName("报名+类名",false(初始化参数，一般写false就行),lpparam.classLoader)：注意一点类加载器必须为同一个
    final Class clazz1 = XposedHelpers.findClass("报名+类名",lpparam.classLoader);
    XposedHelpers.findAndHookMethod(clazz, "methodName", clazz1, new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            super.beforeHookedMethod(param);
        }
    });
}
```





```
 // 7 --- 替换函数：本例为无参数的方法替换
        if (lpparam.packageName.equals("com.baoming")){
            XposedHelpers.findAndHookMethod(clazz, "methodName", new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam methodHookParam) throws Throwable {
                    return null;
                }
            });
        }


        // 8 ---hook内部类匿名类
        if (lpparam.packageName.equals("com.baoming")){
            // 未注释部分hook的是内部类，若是hook匿名类需要将XposedHelpers.findAndHookMethod(XposedHelpers.findClass中的
            //一个个参数修改未“com.example.Demo$1”(注释：$1表示第一个匿名类，有多个匿名类$2,$3)
            // 举例：若要hook第二个匿名类  需要将参数改为“com.example.Demo$2”表示hook第二个匿名类，依次类推
            XposedHelpers.findAndHookMethod(XposedHelpers.findClass("com.example.Demo$Inner", lpparam.classLoader),
                    "内部类方法名",
                    String.class,   // 内部类参数类型，上文有提到
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            super.beforeHookedMethod(param);
                            // XposedHelpers.callMethod表示调用普通方法
                            // 第一个参数表示实例对象，第二个参数实例对象调用的方法，第三个参数，方法的参数
                            // 当然也可以用java反射实现，其实这就是反射呀
                            XposedHelpers.callMethod(clazz.newInstance(),"方法名",new Object[0]);
                            // 获取成员字段（public修饰的字段） param.thisObject 顾名思义就是这个参数的所属对象
                            // 当然也可以用clazz.newInstance()替代,但当前是内部类，注意修改
                            int int1 = XposedHelpers.getIntField(param.thisObject,"fieldName");
                            StringBuffer sb = new StringBuffer();
                            sb.append(BuildConfig.FLAVOR); // 里面的参数是自动生成的，不能修改，值为空字符串，（java内容）
                            sb.append(int1);
                            Log.d("tag",sb.toString());
                            
                        }
                    });
        };
    }
}
```

# arm汇编指令

```
push	{r11, lr}		@保存寄存器lr, r11到栈里面, lr记录函数的返回地址
mov	r11, sp				@把sp赋值给r11  寄存器寻址
sub	sp, sp, #24			@sp=sp-24	@sub rm, rn, #24 rm=rn-24
mov	r2, #0				@r2=0			立即数寻址
str	r2, [r11, #-4]		@把r2的值存到r11-4的地址上		基址寻址
str	r0, [r11, #-8]		@把r0的值存到r11-8的地址上		基址寻址
str	r1, [sp, #12]		@把r1的值存到sp-12的地址上		基址寻址
ldr	r0, .LCPI0_0		@ldr    r0,  [pc,  #40], 从pc+40读取内容存到r0, PC是当前指令的地址+两条指令长度 0x17a8
add	r0, pc, r0			@r0=pc+r0
bl	printf			    @子程序的调用， r0~r3传递参数， 大于4个参数的时候，多的参数用栈传参数， si单步步入， 
					   @r0用作返回值
pop	{r11, lr}			@恢复r11, lr
bx	lr				    @bx lr， 跳转到lr地址， arm -> thumb 或者 thumb -> arm

mov r0, r1, LSL #4       @ r0 = r1 << 4
mov r0, r0, LSR #2     	 @ r0 = r0 >> 2
ldr r0, =0x2			@ =0x2
ldr r0, [r3]			@ r0 = *r3
ldr r0, [r3, #4]		@ r0 = *(r3+4)
ldr r0, [r3, r2, LSL #2] @r0 = *(r3 + (r2 << 2))
@ldr r0, [r3, #4]!		@ r0 = *(r3 + 4), 读完后r3 += 4

cmp r1,#0               @r1寄存器的值与0比较
beq .LABEL_EXIT         @条件成立跳转到.LABEL_EXIT
bne .LABEL_EXIT         @条件不成立跳转到.LABEL_EXIT

立即数寻址
寄存器寻址
寄存器移位寻址
    LSL 逻辑左移
    LSR 逻辑右移
    ROR 循环右移 
    ASR 算术右移
    RRX 扩展的循环右移
   
栈寻址
    stmfd
    ldmfd
    
    ldm r1, {r0,r3}       @连续读取指令    取r1寄存器的值给r0,取r1寄存器的值+4给r3
    stm r1, {r0,r3}       @连续写入指令    取r0寄存器的值写入r1寄存器内值所指向的内存，取r3寄存器的值写入r1寄存器值+4所指向的内存
    
数据处理指令
    mov, add, sub, and, eor, orr, bic

    mov r0, r1
    add r0, r1, r2  @ r0 = r1 + r2
    sub r0, r1, r2  @ r0 = r1 - r2
    and r0, r1, r2  @ r0 = r1 & r2
    eor r0, r1, r2  @ r0 = r1 ^ r2
    orr r0, r1, r2  @ r0 = r1 | r2
    bic r0, r1, #0xF @0x12345678 -> 0x12345670      //

乘法指令
    MUL r0, r1, r2   @ r0 = r1 * r2
    MLA r0, r1, r2, r3  @ r0 = r1 * r2 + r3
    SMULL r0, r1, r2, r3  @ r0 = (r2 * r3)的低32位，r1 = (r2 * r3)的高32位，
    SMLAL r0, r1, r2, r3  @ r0 = (r2 * r3)的低32位 + r0，r1 = (r2 * r3)的高32位 + r1，
    UMULL r0, r1, r2, r3  @ r0 = (r2 * r3)的低32位，r1 = (r2 * r3)的高32位，
    UMLAL r0, r1, r2, r3  @ r0 = (r2 * r3)的低32位 + r0，r1 = (r2 * r3)的高32位 + r1，

内存访问指令
    ldr  4字节读取
    ldrb 1字节读取
    ldrh 2字节读取

    str  4字节写入
    strb 1字节写入
    strh 2字节写入

```

# 	C语言

## 基本数据类型

```c
#include <stdio.h>

int main() {
    int num = 9;
    printf("num:%d size:%d\n", num, sizeof(num));
    float f = 3.14f;
    printf("float:%f size:%d\n", f, sizeof(f));
    double d = 3.14;
    printf("double:%f size:%d\n",d,sizeof(d));
    char c = 'a';
    printf("char:%c size:%d\n",c,sizeof(c));
    char* str = "hello";
    printf("char*:%s size:%d\n",str,sizeof(str));
    return 0;
}


num:9 size:4
float:3.140000 size:4
double:3.140000 size:8
char:a size:1
char*:hello size:8
```

## ptrace使用

`ptrace` 是一个系统调用，主要用于调试和监控另一个进程。它允许一个进程（通常是调试器）观察和控制另一个进程，并且可以改变其执行。`ptrace` 常用于调试工具（如 `gdb`）和进程监控工具中。

### 基本用法

1. **附加到一个进程**： 使用 `ptrace(PTRACE_ATTACH, pid, 0, 0)` 可以附加到目标进程。
2. **分离一个进程**： 使用 `ptrace(PTRACE_DETACH, pid, 0, 0)` 可以从目标进程分离。
3. **读取和写入进程内存**： 使用 `ptrace(PTRACE_PEEKDATA, pid, address, 0)` 读取目标进程的内存，使用 `ptrace(PTRACE_POKEDATA, pid, address, value)` 写入目标进程的内存。
4. **获取和设置寄存器**： 使用 `ptrace(PTRACE_GETREGS, pid, 0, &regs)` 获取寄存器值，使用 `ptrace(PTRACE_SETREGS, pid, 0, &regs)` 设置寄存器值。
5. **单步执行**： 使用 `ptrace(PTRACE_SINGLESTEP, pid, 0, 0)` 让目标进程执行一步。

### 示例代码

下面是一个简单的示例代码，展示了如何使用 `ptrace` 附加到一个进程，读取其寄存器值，并分离该进程：

```c
cCopy code#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/user.h>   /* For user_regs_struct */

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_ATTACH)");
        return 1;
    }

    waitpid(target_pid, NULL, 0);  // Wait for the target process to stop

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, target_pid, NULL, &regs) == -1) {
        perror("ptrace(PTRACE_GETREGS)");
        return 1;
    }

    printf("RIP: %llx\n", regs.rip);  // Print the instruction pointer

    if (ptrace(PTRACE_DETACH, target_pid, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_DETACH)");
        return 1;
    }

    return 0;
}
```

### 说明

1. **附加到目标进程**：

   ```
   c
   Copy code
   ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
   ```

   这会将当前进程附加到目标进程，并停止目标进程的执行。

2. **等待目标进程停止**：

   ```
   c
   Copy code
   waitpid(target_pid, NULL, 0);
   ```

   `waitpid` 用于等待目标进程停止。

3. **获取寄存器值**：

   ```
   c
   Copy code
   ptrace(PTRACE_GETREGS, target_pid, NULL, &regs);
   ```

   这会将目标进程的寄存器值存储到 `regs` 结构体中。

4. **打印指令指针**：

   ```
   c
   Copy code
   printf("RIP: %llx\n", regs.rip);
   ```

   `regs.rip` 保存了目标进程的指令指针（在 x86_64 架构下）。

5. **分离目标进程**：

   ```
   c
   Copy code
   ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
   ```

   这会从目标进程分离，允许其继续执行。

### 注意事项

- `ptrace` 的使用需要超级用户权限。
- 被附加的进程会被暂停，直到调试器分离。
- 使用 `ptrace` 进行调试时，进程的状态和行为可能会受到影响，特别是在多线程程序中。
- `ptrace` 调用失败时，通常会返回 `-1` 并设置 `errno` 以指示错误类型。

### 常见错误

- **`EPERM`**：表示没有权限，通常是因为尝试附加到一个不属于同一个用户的进程。
- **`ESRCH`**：表示指定的进程不存在，或者进程已经退出。







