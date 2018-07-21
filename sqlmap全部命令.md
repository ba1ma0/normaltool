Sqlmap全部命令中文详解

    ___
       __H__
 ___ ___[)]_____ ___ ___  {1.2.3.25#dev}
|_ -| . ["]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V          |_|   http://sqlmap.org

Usage: sqlmap.py [options]

Options:
  -h, --help            Show basic help message and exit    //显示基本帮助信息和退出
  -hh                   Show advanced help message and exit //展示高级的帮助信息以及退出
  --version             Show program's version number and exit //展示程序的版本号以及退出
  -v VERBOSE            Verbosity level: 0-6 (default 1) //详细级别0-6(默认为1)

  Target:
    At least one of these options has to be provided to define the   //至少需要提供以下其中的一个来定义目标
    target(s)

    -d DIRECT           Connection string for direct database connection//直接数据库连接的连接字符串
    -u URL, --url=URL   Target URL (e.g. "http://www.site.com/vuln.php?id=1")//目标url
    -l LOGFILE          Parse target(s) from Burp or WebScarab proxy log file//从burpsuit的WebScarab代理日志中解析目标
    -x SITEMAPURL       Parse target(s) from remote sitemap(.xml) file//从远程站点(.xml)文件中解析目标
    -m BULKFILE         Scan multiple targets given in a textual file//从给定的文本文件中批量扫描目标
    -r REQUESTFILE      Load HTTP request from a file//从一个文件中加载HTTP请求
    -g GOOGLEDORK       Process Google dork results as target URLs//将Google dork结果作为目标URLs处理
    -c CONFIGFILE       Load options from a configuration INI file//从配置INI文件中加载选项

  Request:
    These options can be used to specify how to connect to the target URL//以下选项可以被用来指定怎么连接到目标URL

    --method=METHOD     Force usage of given HTTP method (e.g. PUT)//强制给定HTTP使用的方式(比如PUT)
    --data=DATA         Data string to be sent through POST//要通过POST方式发送的字符串数据
    --param-del=PARA..  Character used for splitting parameter values//用于分割参数的字符
    --cookie=COOKIE     HTTP Cookie header value//HTTP cookie头的值
    --cookie-del=COO..  Character used for splitting cookie values//用于分割cookie值的参数
    --load-cookies=L..  File containing cookies in Netscape/wget format//含有cookie的Netscape/wget格式文件
    --drop-set-cookie   Ignore Set-Cookie header from response //从响应中忽略set-cookie标题
    --user-agent=AGENT  HTTP User-Agent header value//Http User-Agent标题的值
    --random-agent      Use randomly selected HTTP User-Agent header value//使用随机选择的HTTP User-Agent标题值
    --host=HOST         HTTP Host header value//HTTP主机标题值
    --referer=REFERER   HTTP Referer header value//HTTP Referer标题值
    -H HEADER, --hea..  Extra header (e.g. "X-Forwarded-For:  .0.0.1")//额外标题(比如:"X-Forwarded-For:  .0.0.1")
    --headers=HEADERS   Extra headers (e.g. "Accept-Language: fr\nETag:  ")//额外标题(比如:"Accept-Language: fr\nETag:  ")
    --auth-type=AUTH..  HTTP authentication type (Basic, Digest, NTLM or PKI)//HTTP身份验证类型(Basic, Digest, NTLM or PKI)
    --auth-cred=AUTH..  HTTP authentication credentials (name:password)//HTTP身份验证凭证(name:password)
    --auth-file=AUTH..  HTTP authentication PEM cert/private key file//HTTP身份验证PEM证书/私钥文件
    --ignore-code=IG..  Ignore HTTP error code (e.g.  )//忽略HTTP错误代码
    --ignore-proxy      Ignore system default proxy settings//忽略系统默认的代理设置
    --ignore-redirects  Ignore redirection attempts//忽略重定向尝试
    --ignore-timeouts   Ignore connection timeouts//忽略连接超时
    --proxy=PROXY       Use a proxy to connect to the target URL//使用代理连接目标URL
    --proxy-cred=PRO..  Proxy authentication credentials (name:password)//代理身份认证凭证(name:password)
    --proxy-file=PRO..  Load proxy list from a file//从一个文件中加载代理列表
    --tor               Use Tor anonymity network//使用Tor匿名网络
    --tor-port=TORPORT  Set Tor proxy port other than default//设置默认的Tor代理端口
    --tor-type=TORTYPE  Set Tor proxy type (HTTP, SOCKS4 or SOCKS5 (default))//设置Tor代理类型(HTTP, SOCKS4 or SOCKS5 (默认))
    --check-tor         Check to see if Tor is used properly//检查Tor是否正确使用
    --delay=DELAY       Delay in seconds between each HTTP request//每次HTTP请求之间延迟几秒
    --timeout=TIMEOUT   Seconds to wait before timeout connection (default 30)//超时连接之前的等待时间(默认30s)
    --retries=RETRIES   Retries when the connection timeouts (default 3)//连接超时时的重试次数(默认3次)
    --randomize=RPARAM  Randomly change value for given parameter(s)//随机改变给定的参数值
    --safe-url=SAFEURL  URL address to visit frequently during testing//测试期间频繁访问的URL地址
    --safe-post=SAFE..  POST data to send to a safe URL//POST数据到一个安全的URL
    --safe-req=SAFER..  Load safe HTTP request from a file//从一个文件中加载安全的HTTP请求
    --safe-freq=SAFE..  Test requests between two visits to a given safe URL//对比测试两个访问的请求并给定其中的一个安全的URL
    --skip-urlencode    Skip URL encoding of payload data//跳过payload中经过URL加密的数据
    --csrf-token=CSR..  Parameter used to hold anti-CSRF token//保存的用于反CSRF令牌的参数
    --csrf-url=CSRFURL  URL address to visit to extract anti-CSRF token//访问以提取反CSRF令牌的URL地址
    --force-ssl         Force usage of SSL/HTTPS//强制使用SSL/HTTPS
    --hpp               Use HTTP parameter pollution method//使用HTTP参数污染方法
    --eval=EVALCODE     Evaluate provided Python code before the request (e.g.
                        "import hashlib;id2=hashlib.md5(id).hexdigest()")//请求之前对python代码进行评估

  Optimization(优化):
    These options can be used to optimize the performance of sqlmap//以下选项可以用来优化sqlmap的性能

    -o                  Turn on all optimization switches//打开所有的优化开关
    --predict-output    Predict common queries output//预测普通查询输出
    --keep-alive        Use persistent HTTP(s) connections//使用持续HTTP(s)连接
    --null-connection   Retrieve page length without actual HTTP response body//无HTTP实际响应体的检索页长度
    --threads=THREADS   Max number of concurrent HTTP(s) requests (default 1)//最大并发HTTP(s)请求数(默认1)

  Injection(注入):
    These options can be used to specify which parameters to test for,
    provide custom injection payloads and optional tampering scripts//这些选项可以用来指定要测试的参数,提供自定义注入有效载荷和可选篡改脚本

    -p TESTPARAMETER    Testable parameter(s)//测试参数
    --skip=SKIP         Skip testing for given parameter(s)//略过给定的参数
    --skip-static       Skip testing parameters that not appear to be dynamic//略过非动态的参数
    --param-exclude=..  Regexp to exclude parameters from testing (e.g. "ses")//用正则表达式剔除测试中一些数据
    --dbms=DBMS         Force back-end DBMS to this value//强制指定后台DBMS为某一特定数据库管理系统(比如"mysql")
    --dbms-cred=DBMS..  DBMS authentication credentials (user:password)//DBMS身份认证凭证(user:password)
    --os=OS             Force back-end DBMS operating system to this value//强制指定后台DBMS操作系统为某一特定值(比如"Windows")
    --invalid-bignum    Use big numbers for invalidating values//用大数表示无效值
    --invalid-logical   Use logical operations for invalidating values//使用逻辑操作符表示无效值
    --invalid-string    Use random strings for invalidating values//使用随机字符串表示无效值
    --no-cast           Turn off payload casting mechanism//关闭payload铸造机制
    --no-escape         Turn off string escaping mechanism//关闭字符串转义机制
    --prefix=PREFIX     Injection payload prefix string//注入payload前缀字符串
    --suffix=SUFFIX     Injection payload suffix string//注入payload后缀字符串
    --tamper=TAMPER     Use given script(s) for tampering injection data//使用给定的脚本来篡改注入数据

  Detection(检测):
    These options can be used to customize the detection phase// 这些选项可用于自定义检测阶段

    --level=LEVEL       Level of tests to perform (1-5, default 1)//要执行的测试级别（1-5，默认值1）
    --risk=RISK         Risk of tests to perform (1-3, default 1)//执行测试的风险级别（1-3，默认值1）
    --string=STRING     String to match when query is evaluated to True//当查询被评估为为真时匹配字符串
    --not-string=NOT..  String to match when query is evaluated to False//当查询被评估为假时匹配字符串
    --regexp=REGEXP     Regexp to match when query is evaluated to True//当查询被评估为为真时用正则去匹配
    --code=CODE         HTTP code to match when query is evaluated to True//当查询被评估为真时用HTTP状态去匹配
    --text-only         Compare pages based only on the textual content//仅根据文本内容比较页面
    --titles            Compare pages based only on their titles//仅根据标题来比较页面

  Techniques(技巧):
    These options can be used to tweak testing of specific SQL injection//以下操作可以被用来调整特定的SQL注入
    techniques

    --technique=TECH    SQL injection techniques to use (default "BEUSTQ")//要使用的SQL注入技巧(默认:"BEUSTQ")
    --time-sec=TIMESEC  Seconds to delay the DBMS response (default 5)//延时DBMS响应的时间(默认 5秒)
    --union-cols=UCOLS  Range of columns to test for UNION query SQL injection//测试UNION查询型sql注入列的范围 
    --union-char=UCHAR  Character to use for bruteforcing number of columns//用于爆破数据库列数目的字符
    --union-from=UFROM  Table to use in FROM part of UNION query SQL injection//用于UNION查询型SQL注入FROM部分的表
    --dns-domain=DNS..  Domain name used for DNS exfiltration attack//用于DNS渗透攻击的域名
    --second-order=S..  Resulting page URL searched for second-order response//结果页面URL用于搜索二阶响应

  Fingerprint(指纹):
    -f, --fingerprint   Perform an extensive DBMS version fingerprint//执行广泛的DBMS版本的指纹

  Enumeration(枚举):
    These options can be used to enumerate the back-end database//下面的操作可用于枚举后台数据库
    management system information, structure and data contained in the//管理系统,结构,表中的数据.
    tables. Moreover you can run your own SQL statements//此外你还可以运行你自己的SQL语句

    -a, --all           Retrieve everything //检索所有
    -b, --banner        Retrieve DBMS banner//检索DBMS banner
    --current-user      Retrieve DBMS current user//检索DBMS当前用户
    --current-db        Retrieve DBMS current database//检索DBMS当前数据库
    --hostname          Retrieve DBMS server hostname//检索DBMS服务器主机名
    --is-dba            Detect if the DBMS current user is DBA//检测当前DBMS用户是否是DBA
    --users             Enumerate DBMS users//枚举DBMS用户名
    --passwords         Enumerate DBMS users password hashes//枚举DBMS用户密码哈希值
    --privileges        Enumerate DBMS users privileges//枚举DBMS用户权限
    --roles             Enumerate DBMS users roles//枚举DBMS用户角色
    --dbs               Enumerate DBMS databases//枚举DBMS用户数据库
    --tables            Enumerate DBMS database tables//枚举DBMS某数据库下对应的数据表格
    --columns           Enumerate DBMS database table columns//枚举DBMS某数据库下某表对应的所有列
    --schema            Enumerate DBMS schema//枚举DBMS详细信息
    --count             Retrieve number of entries for table(s)//检索表的条目数
    --dump              Dump DBMS database table entries//罗列数据库表格条目信息
    --dump-all          Dump all DBMS databases tables entries//罗列所有数据库表格条目信息
    --search            Search column(s), table(s) and/or database name(s)//搜索 列,表 and/or数据库名字
    --comments          Retrieve DBMS comments//检索DBMS注释
    -D DB               DBMS database to enumerate//要枚举的DBMS数据库
    -T TBL              DBMS database table(s) to enumerate//要枚举的DBMS数据库的表
    -C COL              DBMS database table column(s) to enumerate//要枚举的DBMS数据库表的列
    -X EXCLUDE          DBMS database identifier(s) to not enumerate//标识不枚举的DBMS数据库
    -U USER             DBMS user to enumerate//要枚举的DBMS用户
    --exclude-sysdbs    Exclude DBMS system databases when enumerating tables//枚举时排除某个DBMS系统数据库
    --pivot-column=P..  Pivot column name//枢纽列名
    --where=DUMPWHERE   Use WHERE condition while table dumping//当罗列表时使用WHERE条件
    --start=LIMITSTART  First dump table entry to retrieve//罗所有列表时把某个索引当做开头
    --stop=LIMITSTOP    Last dump table entry to retrieve//罗所有列表时把某个索引当做结尾
    --first=FIRSTCHAR   First query output word character to retrieve//首先查询输出字符来检索
    --last=LASTCHAR     Last query output word character to retrieve//最后查询输出字符来检索
    --sql-query=QUERY   SQL statement to be executed//要执行的SQL语句
    --sql-shell         Prompt for an interactive SQL shell//为交互式SQL shell提示
    --sql-file=SQLFILE  Execute SQL statements from given file(s)//从一个文件中加载并执行SQL语句

  Brute force(暴力):
    These options can be used to run brute force checks//以下操作可用来暴力破解检查

    --common-tables     Check existence of common tables//检查公共表存在性
    --common-columns    Check existence of common columns//检查公共列存在性

  User-defined function injection(用户自定义函数注入):
    These options can be used to create custom user-defined functions//以下操作可用来创建用户自定义函数

    --udf-inject        Inject custom user-defined functions//注入用户自定义函数
    --shared-lib=SHLIB  Local path of the shared library//共享库的本地路径

  File system access(文件系统访问):
    These options can be used to access the back-end database management//以下操作可以用来访问后台数据管理的系统底层文件系统
    system underlying file system

    --file-read=RFILE   Read a file from the back-end DBMS file system//读取后台DBMS文件系统的一个文件
    --file-write=WFILE  Write a local file on the back-end DBMS file system//在DBMS文件系统后台写入一个本地文件
    --file-dest=DFILE   Back-end DBMS absolute filepath to write to//要写入的后台DBMS的绝对路径

  Operating system access(操作系统访问):
    These options can be used to access the back-end database management//以下操作可以用来访问后台数据库管理系统的底层操作系统
    system underlying operating system

    --os-cmd=OSCMD      Execute an operating system command//执行一个操作系统命令
    --os-shell          Prompt for an interactive operating system shell//为交互式操作系统shell提示
    --os-pwn            Prompt for an OOB shell, Meterpreter or VNC//为一个OOB shell,Meterpreter或者VNC提示
    --os-smbrelay       One click prompt for an OOB shell, Meterpreter or VNC//单击提示输入OOB shell，Meterpreter或VNC
    --os-bof            Stored procedure buffer overflow exploitation//存储过程缓冲区溢出利用
    --priv-esc          Database process user privilege escalation//数据库进程用户权限提升
    --msf-path=MSFPATH  Local path where Metasploit Framework is installed//安装Metasploit框架的本地路径
    --tmp-path=TMPPATH  Remote absolute path of temporary files directory//临时文件目录的远程绝对路径

  Windows registry access(Windows注册表访问):
    These options can be used to access the back-end database management//以下操作可以用来访问后台数据库管理系统Windows注册表
    system Windows registry

    --reg-read          Read a Windows registry key value//读取Windows注册表项的值
    --reg-add           Write a Windows registry key value data//对Windows注册表项写入数据
    --reg-del           Delete a Windows registry key value//删除Windows注册表项值
    --reg-key=REGKEY    Windows registry key//Windows注册表项
    --reg-value=REGVAL  Windows registry key value//Windows注册表项值
    --reg-data=REGDATA  Windows registry key value data//Windows注册表项数据
    --reg-type=REGTYPE  Windows registry key value type//Windows注册表项值类型

  General(常用):
    These options can be used to set some general working parameters//这些选项可用于设置一些常规工作参数

    -s SESSIONFILE      Load session from a stored (.sqlite) file//从一个存储的(.sqllite)文件中加载会话
    -t TRAFFICFILE      Log all HTTP traffic into a textual file//将所有HTTP流量记录到文本文件中
    --batch             Never ask for user input, use the default behavior//使用默认选项,永不让用户输入
    --binary-fields=..  Result fields having binary values (e.g. "digest")//结果字段具有二进制值(比如."digest")
    --check-internet    Check Internet connection before assessing the target//在评估目标之前检查Internet连接
    --crawl=CRAWLDEPTH  Crawl the website starting from the target URL//从目标网址开始抓取网站
    --crawl-exclude=..  Regexp to exclude pages from crawling (e.g. "logout")//正则表达式从抓取中排除页面
    --csv-del=CSVDEL    Delimiting character used in CSV output (default ",")//在CSV输出中使用的分隔字符（默认值,","）
    --charset=CHARSET   Blind SQL injection charset (e.g. "   9abcdef")//盲注字符集(比如:'9abcdef')
    --dump-format=DU..  Format of dumped data (CSV (default), HTML or SQLITE)//枚举出的数据输出存储格式(CSV(默认),HTML,SQLITE)
    --encoding=ENCOD..  Character encoding used for data retrieval (e.g. GBK)//用于数据检索的字符编码(比如:GBK)
    --eta               Display for each output the estimated time of arrival//显示每个输出的预计到达时间
    --flush-session     Flush session files for current target//刷新当前目标的会话文件
    --forms             Parse and test forms on target URL//在目标URL上解析和测试表单
    --fresh-queries     Ignore query results stored in session file//忽略存储在会话文件中的查询结果
    --har=HARFILE       Log all HTTP traffic into a HAR file//将所有HTTP流量记录到HAR文件中
    --hex               Use DBMS hex function(s) for data retrieval//使用DBMS十六进制函数进行数据检索
    --output-dir=OUT..  Custom output directory path//自定义输出文件路径
    --parse-errors      Parse and display DBMS error messages from responses//从响应中解析并显示DBMS错误消息
    --save=SAVECONFIG   Save options to a configuration INI file//将选项保存到配置INI文件
    --scope=SCOPE       Regexp to filter targets from provided proxy log//用正则表达式从代理日志中筛选目标
    --test-filter=TE..  Select tests by payloads and/or titles (e.g. ROW)//通过有效载荷和/或标题选择测试（例如行）
    --test-skip=TEST..  Skip tests by payloads and/or titles (e.g. BENCHMARK)//通过有效载荷和/或标题跳过测试（例如基准测试）
    --update            Update sqlmap//更新sqlmap

  Miscellaneous(其他):
    -z MNEMONICS        Use short mnemonics (e.g. "flu,bat,ban,tec=EU")//使用短助记符（例如“flu，bat，ban，tec = EU”）
    --alert=ALERT       Run host OS command(s) when SQL injection is found//找到SQL注入时运行主机系统命令
    --answers=ANSWERS   Set question answers (e.g. "quit=N,follow=N")//设置问题答案（例如“quit = N，follow = N”）
    --beep              Beep on question and/or when SQL injection is found//当问题和/或发现SQL注入时发出哔哔声
    --cleanup           Clean up the DBMS from sqlmap specific UDF and tables//从特定于sqlmap的UDF和表中清除DBMS
    --dependencies      Check for missing (non-core) sqlmap dependencies//检查缺失的（非核心）sqlmap依赖项
    --disable-coloring  Disable console output coloring//禁用控制台输出着色
    --gpage=GOOGLEPAGE  Use Google dork results from specified page number//使用特定页码的Google dork结果
    --identify-waf      Make a thorough testing for a WAF/IPS/IDS protection//对WAF / IPS / IDS保护进行全面测试
    --mobile            Imitate smartphone through HTTP User-Agent header//通过HTTP User-Agent标头模仿智能手机
    --offline           Work in offline mode (only use session data)//离线模式工作(只使用会话信息)
    --purge-output      Safely remove all content from output directory//安全删除输出目录中的所有内容
    --skip-waf          Skip heuristic detection of WAF/IPS/IDS protection//跳过WAF/IPS/IDS保护的启发式检测
    --smart             Conduct thorough tests only if positive heuristic(s)//只有在积极启发式的情况下才能进行彻底的测试
    --sqlmap-shell      Prompt for an interactive sqlmap shell//提示交互式sqlmap shell
    --tmp-dir=TMPDIR    Local directory for storing temporary files//用于存储临时文件的本地目录/
    --web-root=WEBROOT  Web server document root directory (e.g. "/var/www")//web服务文件根目录(比如:"/var/www")
    --wizard            Simple wizard interface for beginner users//简单的向导界面，适合初学者用户
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++	
	
	   Tampers(第三插件)			Requirement		作用                       实例
     apostrophemask.py                              用utf8代替引号    ("1 AND '1'='1")   '1 AND %EF%BC%871%EF%BC%87=%EF%BC%871'
     apostrophenullencode.py                        绕过过滤双引号，替换字符和双引号      tamper("1 AND '1'='1") '1 AND %00%271%00%27=%00%271'
     appendnullbyte.py								在有效负荷结束位置加载零字节字符编码   ('1 AND 1=1') '1 AND 1=1%00'
     base64encode.py				all				用base64编码替换		("1' AND SLEEP(5)#")   'MScgQU5EIFNMRUVQKDUpIw=='	
     between.py						all             用between替换大于号（>）('1 AND A &gt; B--')   '1 AND A NOT BETWEEN 0 AND B--'
     bluecoat.py					all				代替空格字符后与一个有效的随机空白字符的SQL语句。然后替换=为like ('SELECT id FROM users where id = 1')  'SELECT%09id FROM users where id LIKE 1' 
     chardoubleencode.py                            双url编码(不处理已编码的)    
     charencode.py                                  url编码
     charunicodeencode.py            字符串 unicode 编码
     charunicodeescape.py
     commalesslimit.py
     commalessmid.py
     commentbeforeparentheses.py
     concat2concatws.py
     equaltolike.py                  like 代替等号     Input: SELECT * FROM users WHERE id=1  * Output: SELECT * FROM users WHERE id LIKE 1
     escapequotes.py
     greatest.py                      绕过过滤’>’ ,用GREATEST替换大于号   ('1 AND A &gt; B') '1 AND GREATEST(A,B+1)=A'
     halfversionedmorekeywords.py     当数据库为mysql时绕过防火墙，每个关键字之前添加mysql版本评论  
     htmlencode.py
     ifnull2casewhenisnull.py
     ifnull2ifisnull.py               绕过对 IFNULL 过滤 替换类似’IFNULL(A, B)’为’IF(ISNULL(A), B, A)’     
     informationschemacomment.py
     least.py
     lowercase.py
     modsecurityversioned.py		MYSQL			过滤空格，包含完整的查询版本注释     ('1 AND 2&gt;1--')  '1 /*!30874AND 2&gt;1*/--'
     modsecurityzeroversioned.py					包含了完整的查询与零版本注释         ('1 AND 2&gt;1--')   '1 /*!00000AND 2&gt;1*/--'
     multiplespaces.py								围绕SQL关键字添加多个空格             ('1 UNION SELECT foobar') '1    UNION     SELECT   foobar'
     nonrecursivereplacement.py   双重查询语句。取代predefined SQL关键字with表示 suitable for替代（例如  .replace（“SELECT”、””)） filters     ('1 UNION SELECT 2--')  '1 UNIOUNIONN SELESELECTCT 2--'
     overlongutf8.py    
     overlongutf8more.py
     percentage.py              asp允许每个字符前面添加一个%号   * Input: SELECT FIELD FROM TABLE  'SELECT%0Did%0DFROM%0Ausers'
     plus2concat.py
     plus2fnconcat.py
     randomcase.py                   随机大小写
     randomcomments.py               用/**/分割sql关键字    ‘INSERT’ becomes ‘IN//S//ERT’
     securesphere.py             追加特制的字符串 ('1 AND 1=1') "1 AND 1=1 and '0having'='0having'"
     space2comment.py          Replaces space character (‘ ‘) with comments ‘/**/’
     space2dash.py             绕过过滤‘=’ 替换空格字符（”），（’ – ‘）后跟一个破折号注释，一个随机字符串和一个新行（’ n’）  ('1 AND 9227=9227')  '1--nVNaVoPYeva%0AAND--ngNvzqu%0A9227=9227'
     space2hash.py             空格替换为#号 随机字符串 以及换行符     * Input: 1 AND 9227=9227  * Output: 1%23PTTmJopxdWJ%0AAND%23cWfcVRPV%0A9227=9227
     space2morecomment.py
     space2morehash.py         空格替换为 #号 以及更多随机字符串 换行符  * Input: 1 AND 9227=9227    * Output: 1%23PTTmJopxdWJ%0AAND%23cWfcVRPV%0A9227=9227    
     space2mssqlblank.py       空格替换为其它空符号   * Input: SELECT id FROM users  * Output: SELECT%08id%02FROM%0Fusers
     space2mssqlhash.py
     space2mysqlblank.py		  MYSQL				空格替换其它空白符号(mysql)   * Input: SELECT id FROM users    * Output: SELECT%0Bid%0BFROM%A0users		
     space2mysqldash.py			  mysql				替换空格字符（”）（’ – ‘）后跟一个破折号注释一个新行（’ n’）
     space2plus.py									用+替换空格											('SELECT id FROM users') 'SELECT+id+FROM+users'
     space2randomblank.py                     代替空格字符（“”）从一个随机的空白字符可选字符的有效集   ('SELECT id FROM users')  'SELECT%0Did%0DFROM%0Ausers'
     sp_password.py                      追加sp_password’从DBMS日志的自动模糊处理的有效载荷的末尾
     symboliclogical.py   
     unionalltounion.py                  替换UNION ALL SELECT为UNION SELECT
     unmagicquotes.py                    宽字符绕过 GPC  addslashes      * Input: 1′ AND 1=1   * Output: 1%bf%27 AND 1=1–%20
     uppercase.py
     varnish.py
     versionedkeywords.py          用版本化的MySQL注释封装每个非函数关键字
     versionedmorekeywords.py      注释绕过
     xforwardedfor.py