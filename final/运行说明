dns_local.txt为北邮服务器的cache，目前能运行的命令有:
./client 主页.北邮.教育.中国 A
./client 主页.北邮.教育.中国 CNAME
./client 北邮.教育.中国 MX
编译命令和运行命令：

1、[client]
gcc client.c packet.c -o client
./client 主页.北邮.教育.中国 A

2、[server_local]
gcc server_local.c packet.c -o server_local
sudo ./server_local

3、[server_root] 
gcc server_root.c packet.c -o server_root
sudo ./server_root

4、[server_tld] 
gcc server_tld.c packet.c -o server_tld
sudo ./server_tld

5、[server_2nd] 
gcc server_2nd.c packet.c -o server_2nd
sudo ./server_2nd

6、[server_bupt] 
gcc server_bupt.c packet.c -o server_bupt
sudo ./server_bupt
