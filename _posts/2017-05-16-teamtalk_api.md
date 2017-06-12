---
layout: post
title:  teamtalk API
date: 2017-05-16 10:56:48 +0800
category: teamtalk
author: xiaominfc
description: teamtalk API
---


# teamtalk 使用的API

## HTTP API(http_msg_server)

#### 默认应答

~~~~
{
	"error_code":0,//非0值则为失败了
	"error_msg": "成功"//附加信息
}
~~~~

### baseurl:http://ip:8400/

### url必带的参数(可以任意填写 因为默认并没有实现相关的作用)

~~~~
app_key: 验证
req_user_id: 验证
~~~~

### action:post  data_type:json
## 批量用户推送接口

给一批用户发通知 这样减少http的请求次数

### POST query/SendBroadCastMessage

#### data_type:json

#### parameters:
~~~~
req_user_id: 发送者ID
session_ids: 接收者ID数组
msg: 消息内容 可以用特殊格式如json封装
msg_type: 默认用3（新定义的 用于推送通知） 1 用户文本消息 2 用户音频 17 群文本消息 18 群音频消息
~~~~  
 

#### example:
~~~~  
{
    "from_user_id":8,
    "session_ids":[1,2],
    "msg":"{\"url:\",\"http://ip/note/id\"}",
    "msg_type":3
}

客户端需要对消息类型为3的消息 特殊处理以及解析 json封装的会是种约定好的格式
~~~~



## 推送接口
给指定用户 通过http发送消息

### POST /query/SendP2PMessage
#### data_type:json

#### parameters:
~~~~
req_user_id: 发送者ID
session_id: 接收者ID
msg: 消息内容 可以用特殊格式如json封装
msg_type: 默认用3（新定义的 用于推送通知） 1 用户文本消息 2 用户音频 17 群文本消息 18 群音频消息 
~~~~

#### example:

~~~~

{
    "from_user_id":8,
    "session_id":1,
    "msg":"{\"url:\",\"http://www.mworldex.com/note/id\"}",
    "msg_type":3
}
~~~~

客户端需要对消息类型为3的消息 特殊处理以及解析 json封装的会是种约定好的格式



## 创建群
客户端只能创建临时群  这个http的api可用于创建正式群

### POST /query/CreateGroup
#### data_type:json

#### parameters:

~~~~
req_user_id: 请求创建群的用户ID
group_name: 创建群的名称
group_type: 群类型
group_avatar: 群icon的url
user_id_list: 群成员
~~~~

#### example:

~~~~
{
    "req_user_id":1,
    "group_name":"测试群",
    "group_type":1,
    "group_avatar":"http://dadsd/dsds/icon.png",
    "user_id_list":[1]
}
~~~~


## 修改群成员
客户端走tcp的接口也有 不过通过这个也能达到目的 就是得到服务端的反馈内容会少些

### POST /query/ChangeMembers

#### data_type:json

#### paramters:

~~~~
from_user_id: 请求修改群成员的用户ID
group_id: 操作的群ID
modify_type: 修改行为 1:add 2:remove
user_id_list: 被操作的用户ID列表
~~~~

#### example:
~~~~
{
    "req_user_id":1,
    "group_id":123,
    "modify_type":1,
    "user_id_list":[1]
}
~~~~

## 上传图片（msfs） 
### POST http://ip:8700/

#### data_type:multipart/form-data

~~~~
filename=filepath
~~~~

#### curl example

~~~~
curl -F "filename=@./head.jpeg" http://ip:8700/
~~~~

#### 应答

~~~~
{
    "error_code":0,
    "error_msg": "成功",
    "path":"g0/000/000/1468217208421049_140410609219.jpeg", 
    "url":"http://ip:8700/g0/000/000/1468217208421049_140410609219.jpeg"
}
~~~~


## TCP数据包(与msg_server交互用的)
向msg_server发送的每个数据包是由16个字节长度的头加上对应的pb(google buffer protocol)序列化后的字节数组组成
header+pb

header的结构如下
~~~~
typedef struct {
	uint32_t 	length;		  // 整个包的长度(16+pb序列化字节数组的长度)
	uint16_t 	version;	  // 版本号
	uint16_t	flag;		  // 保留
	uint16_t	service_id;	  // 决定pb的种类
	uint16_t	command_id;	  // 决定pb具体实例化用的类
	uint16_t	seq_num; // 包序号
	uint16_treversed;// 保留
	} PduHeader_t;
~~~~
seq_num 对于每个request服务端返回的response中的seq_num是一样的。他的目的就是为了标示这个应答是对应哪个请求的


## 各种pb
### 一.登录相关

~~~~
//service_idSID_LOGIN(0x0001)
~~~~

#### 1.登录请求
##### 请求：IMLoginReq

~~~~
//service_idSID_LOGIN(0x0001)
//cmd id:	CID_LOGIN_REQ_USERLOGIN(0x0103)

message IMLoginReq{
	required string user_name = 1;//用户名
	required string password = 2; //密码MD5
	required IM.BaseDefine.UserStatType online_status = 3;//状态(登录时用在线 更多可看IM.BaseDefine.UserStatType)
	required IM.BaseDefine.ClientType client_type = 4;//客户端类型
	optional string client_version = 5;   //客户端的版本号
}
~~~~

##### 应答：IMLoginRes

~~~~
//service_idSID_LOGIN(0x0001)
//cmd id:	CID_LOGIN_RES_USERLOGIN(0x0104)

message IMLoginRes{
	required uint32 server_time = 1;   //时间戳
	required IM.BaseDefine.ResultType result_code = 2; //登录结果(0成功)
	optional string result_string = 3; //登录失败返回信息
	optional IM.BaseDefine.UserStatType online_status = 4; //登录状态
	optional IM.BaseDefine.UserInfo user_info = 5; //登录用户的信息(用户名之类的基本信息)
}
~~~~


#### 2.退出登录
##### 请求：IMLogoutReq

~~~~
//service_idSID_LOGIN(0x0001)
//cmd id:	CID_LOGIN_REQ_LOGINOUT(0x0105)
message IMLogoutReq{

}
~~~~

##### 应答：IMLogoutRsp

~~~~
//cmd id:	CID_LOGIN_RES_LOGINOUT(0x0106)

message IMLogoutRsp{
	required uint32 result_code = 1; //登出反馈
}
~~~~


### 二.用户相关

~~~~
//service_idSID_BUDDY_LIST(0x0002)
~~~~

#### 1.请求用户列表
每次登录后都得进行的请求根据latest_update_time跟服务端做用户列表的差分达到同步最新用户列表的目的
#### 请求:IMAllUserReq

~~~~
//cmd id:	CID_BUDDY_LIST_ALL_USER_REQUES(0x0208)

message IMAllUserReq{
	//cmd id:		0x0208
	required uint32 user_id = 1;   //用户id
	required uint32 latest_update_time = 2;//上次更新时间(服务端得根据这个时间戳比较出新用户以及被修改的用户 若为0则返回所有的用户列表)
	optional bytes attach_data = 20;   //服务端用 保留
}
~~~~

#### 应答:IMAllUserRsp

~~~~
//cmd id:	CID_BUDDY_LIST_ALL_USER_RESPONSE(0x0209)


message IMAllUserRsp{
	//cmd id:		0x0209
	required uint32 user_id = 1;  //用户id
	required uint32 latest_update_time = 2;   //最新时间戳 保存到本地 下次请求时用
	repeated IM.BaseDefine.UserInfo user_list = 3;//用户列表
	optional bytes attach_data = 20;
}
~~~~


#### 2.请求部门列表
与获取用户列表的类似 都要达到获取最新的列表
#### 请求:IMDepartmentReq

~~~~
//cmd id:   CID_BUDDY_LIST_DEPARTMENT_REQUEST(0x0210)

message IMDepartmentReq{
	//cmd id:		0x0210
	required uint32 user_id = 1;   //用户id
	required uint32 latest_update_time = 2;//上次更新时间
	optional bytes attach_data = 20;
}
~~~~

#### 应答：IMDepartmentRsp

~~~~
//cmd id:   CID_BUDDY_LIST_DEPARTMENT_RESPONSE(0x0211)

message IMDepartmentRsp{
	//cmd id:		0x0211
	required uint32 user_id = 1;//用户ID
	required uint32 latest_update_time = 2; //最新时间戳 保存到本地 下次请求时用
	repeated IM.BaseDefine.DepartInfo dept_list = 3;//部门列表
	optional bytes attach_data = 20;
}
~~~~


#### 3.请求最近聊天会话列表
##### 请求：IMRecentContactSessionReq

~~~~
//cmd id:   CID_BUDDY_LIST_RECENT_CONTACT_SESSION_REQUEST(x0201)

message IMRecentContactSessionReq{
//cmd id:		0x0201
required uint32 user_id = 1;
required uint32 latest_update_time = 2;//本地会话列表中的最大时间戳(若没有就用0 则返回全部的了)
optional bytes attach_data = 20;
}
~~~~


##### 应答：IMRecentContactSessionRsp

~~~~
//cmd id:   CID_BUDDY_LIST_RECENT_CONTACT_SESSION_RESPONSE(x0202)

message IMRecentContactSessionRsp{
	//cmd id:		0x0202
	required uint32 user_id = 1;
	repeated IM.BaseDefine.ContactSessionInfo contact_session_list = 2;//会话列表
	optional bytes attach_data = 20;
}
~~~~


#### 4.移除会话(session)

~~~~
	//cmd id:		CID_BUDDY_LIST_REMOVE_SESSION_REQ 0x0206
message IMRemoveSessionReq{
	//cmd id:		0x0206
	required uint32 user_id = 1;
	required IM.BaseDefine.SessionType session_type = 2; //群聊 或者单聊
	required uint32 session_id = 3;  //对方ID或者群号
	optional bytes attach_data = 20;
}
~~~~



### 三.群聊相关

~~~~
//service_idSID_GROUP(0x0004)
~~~~

#### 1.请求群聊列表
 
##### 请求：IMNormalGroupListReq

~~~~
//cmd id:   CID_GROUP_NORMAL_LIST_REQUEST(0x0401)

message IMNormalGroupListReq{
	//cmd id:			0x0401
	required uint32 user_id = 1;//用户ID
	optional bytes attach_data = 20;
}
~~~~


##### 应答：IMNormalGroupListRsp

~~~~
//cmd id:   CID_GROUP_NORMAL_LIST_RESPONSE(0x0402)

message IMNormalGroupListRsp{
	//cmd id:			0x0402
	required uint32 user_id = 1;   //用户ID
	repeated IM.BaseDefine.GroupVersionInfo group_version_list = 2;//群聊列表，每个GroupVersionInfo都会包含群的ID以及一个version(用于后续请求群详情)
	optional bytes attach_data = 20;
}
~~~~



#### 2.请求群详情:
前面的API只能获取到用户所在的群号(通过用户与群的关系表查得。所以再用这个接口获取群的具体详情)
这个API还可以更新本地存储的群详情(每次修改群相关信息,群的version就会加1。所以把本地的群的version发送过过去就能知道该群有没有被修改了)
##### 请求：IMGroupInfoListReq

~~~~
//cmd id:   CID_GROUP_INFO_REQUEST(0x0403)

message IMGroupInfoListReq{
	//cmd id:			0x0403
	required uint32 user_id = 1;//用户id
	repeated IM.BaseDefine.GroupVersionInfo group_version_list = 2; //第一次请求时 group_version_list中的每个GroupVersionInfo的version设置为0 服务端会只会返回比version大的群的详情
	optional bytes attach_data = 20;
}
~~~~


##### 应答：IMGroupInfoListRsp

~~~~
//cmd id:   CID_GROUP_INFO_RESPONSE(0x0404)

message IMGroupInfoListRsp{
	//cmd id:			0x0404
	required uint32 user_id = 1;
	repeated IM.BaseDefine.GroupInfo group_info_list = 2;//群详情的列表（群名以及相关基本信息）
	optional bytes attach_data = 20;
}
~~~~

#### 3.创建群
##### 请求:IMGroupCreateReq

~~~~
//cmd id:			(CID_GROUP_CREATE_REQUEST)0x0405

message IMGroupCreateReq{
	//cmd id:			0x0405
	required uint32 user_id = 1;
	required IM.BaseDefine.GroupType group_type = 2 [default = GROUP_TYPE_TMP];//默认是创建临时群，且客户端只能创建临时群
	required string group_name = 3;   //群的名称
	required string group_avatar = 4; //群头像
	repeated uint32 member_id_list = 5;   //群初始化成员列表(相关用户id数组)
	optional bytes attach_data = 20;
}
~~~~


##### 应答:IMGroupCreateRsp

~~~~
//cmd id:(CID_GROUP_CREATE_REQUEST)0x0406
message IMGroupCreateRsp{
	//cmd id:			0x0406
	required uint32 user_id = 1;
	required uint32 result_code = 2; //创建成功的状态值
	optional uint32 group_id = 3;
	required string group_name = 4;
	repeated uint32 user_id_list = 5;
	optional bytes attach_data = 20;
}
~~~~


#### 4.修改群成员列表
##### 请求：IMGroupChangeMemberReq

~~~~
//cmd id:（CID_GROUP_CHANGE_MEMBER_REQUEST）0x0407

message IMGroupChangeMemberReq{
	//cmd id:			0x0407
	required uint32 user_id = 1;//操作的用户ID
	required IM.BaseDefine.GroupModifyType change_type = 2; //1：添加 2：移除
	required uint32 group_id = 3;   //群ID
	repeated uint32 member_id_list = 4; //被操作的用户ID数组
	optional bytes attach_data = 20;
}
~~~~


##### 应答：IMGroupChangeMemberRsp

~~~~
//cmd id:（CID_GROUP_CHANGE_MEMBER_RESPONSE）0x0408

message IMGroupChangeMemberRsp{
	//cmd id:			0x0408
	required uint32 user_id = 1;
	required IM.BaseDefine.GroupModifyType change_type = 2;  
	required uint32 result_code = 3; //操作结果
	required uint32 group_id = 4;   
	repeated uint32 cur_user_id_list = 5;	  //现有的成员id		
	repeated uint32 chg_user_id_list = 6;		  //变动的成员id,add: 表示添加成功的id,   del: 表示删除的id
	optional bytes attach_data = 20;
}
~~~~


### 四.聊天相关
~~~~
//service_idSID_MSG(0x0003)
~~~~

#### 1.发送消息以及新消息
##### 请求：IMMsgData
客户端端向服务端发消息以及收到的新消息都是用这个封装

~~~~
//cmd id:CID_MSG_DATA(0x0301)

message IMMsgData{
	//cmd id:		0x0301
	required uint32 from_user_id = 1;			   //消息发送方(用户ID)
	required uint32 to_session_id = 2;			   //消息接受方(接收用户的ID或者接收的群ID)
	required uint32 msg_id = 3;  //若是发送则为0
	required uint32 create_time = 4; //消息创建的时间
	required IM.BaseDefine.MsgType msg_type = 5; //消息类型(单聊文本 单聊图片 单聊语音 群聊文本 群聊图片 群聊语音)
	required bytes msg_data = 6; //消息内容(aes-256-nopadding加密)
	optional bytes attach_data = 20;
}
~~~~

##### 应答(发送成功后服务端返回的):IMMsgDataAck

~~~~
//cmd id:CID_MSG_DATA_ACK(0x0302)

message IMMsgDataAck{
	//cmd id:		0x0302
	required uint32 user_id = 1;			 //发送此信令的用户id
	required uint32 session_id = 2;				 //接收用户或群的ID 
	required uint32 msg_id = 3; //>0的值
	required IM.BaseDefine.SessionType session_type = 4;//标记类型单聊 群聊
}
~~~~


##### 应答(应答来自服务器给你发的新消息):IMMsgDataReadAck
结构与IMMsgDataAck类似。就是接收到新消息后用这个给服务器反馈说你读到了

~~~~
//cmd id:CID_MSG_READ_ACK(0x0303)
message IMMsgDataReadAck{
	//cmd id:		0x0303
	required uint32 user_id = 1;			//发送此信令的用户id
	required uint32 session_id = 2;			
	required uint32 msg_id = 3;
	required IM.BaseDefine.SessionType session_type = 4;
}
~~~~

#### 2.获取未读消息数量
##### 请求：IMUnreadMsgCntReq

~~~~
//cmd_id:  CID_MSG_UNREAD_CNT_REQUEST(0x0307)

message IMUnreadMsgCntReq{
	//cmd id:		0x0307
	required uint32 user_id = 1;  
	optional bytes attach_data = 20;	
}
~~~~

##### 应答：IMUnreadMsgCntRsp

~~~~
//cmd_id:  CID_MSG_UNREAD_CNT_RESPONSE(0x0308)

message IMUnreadMsgCntRsp{
	//cmd id:		0x0308
	required uint32 user_id = 1;
	required uint32 total_cnt = 2;//未读消息的总数
	repeated IM.BaseDefine.UnreadInfo unreadinfo_list = 3;//未读消息列(每个UnreadInfo都会包含对最近会话列表进行跟新的相关信息)
	optional bytes attach_data = 20;
}
~~~~

#### 3.获取消息列表(加载聊天历史之类的操作)

##### 请求：IMGetMsgListReq

~~~~
//cmd id:CID_MSG_LIST_REQUEST(0x0309)
	
message IMGetMsgListReq{
	//cmd id:		0x0309
	required uint32 user_id = 1;
	required IM.BaseDefine.SessionType session_type = 2; //单聊 群聊
	required uint32 session_id = 3;  //用户ID或者群ID
	required uint32 msg_id_begin = 4;//0 则返回最新的msg_cnt条 否则返回比msg_id_begin小于或等于的msg_cnt条记录
	required uint32 msg_cnt = 5; //要请求的个数
	optional bytes attach_data = 20;
}
~~~~

##### 应答：IMGetMsgListRsp
群聊只能获取到用户加群以后的聊天记录

~~~~
	//cmd id:CID_MSG_LIST_RESPONSE(0x030a)
	
message IMGetMsgListRsp{
	//cmd id:		0x030a
	required uint32 user_id = 1;
	required IM.BaseDefine.SessionType session_type = 2; 
	required uint32 session_id = 3;   
	required uint32 msg_id_begin = 4;
	repeated IM.BaseDefine.MsgInfo msg_list = 5; //消息列表
	optional bytes attach_data = 20;
}
~~~~

### 五.文件传输相关

~~~~
	1.创建好一个文件传输的task，客户端会连接file_server验证身份，接着会收到file_server的拉流请求(接收方在线则是转发接收方的拉流请求,若是离线传输则是file_server自动生成)，根据拉流请求的偏移。客户端应答后续定量(32768字节)的文件文件偏移一直到传输完整。
	2.离线文件的下载。 客户端也要连接file_server验证身份，然后进行拉流请求直到离线文件传输完整
	3.离线文件传输结束后，需要通知msg_server把这个离线文件传输的task通过db_proxy_server写入数据库


//service_idSID_FILE(0x0005)
~~~~

#### 1.创建一个文件传输的任务

##### 请求:IMFileReq

~~~~
//cmd id: 	CID_FILE_REQUEST 0x0506

message IMFileReq{
	//cmd id: 	0x0506
	required uint32 from_user_id = 1;  //发送方ID
	required uint32 to_user_id = 2;//接收方ID
	required string file_name = 3; //文件路径
	required uint32 file_size = 4; //文件大小
	required IM.BaseDefine.TransferFileType trans_mode = 5;//在线或离线
}
~~~~

##### 应答:IMFileRsp

~~~~
	//cmd id: 	CID_FILE_RESPONSE 0x0507
message IMFileRsp{
	//cmd id: 	0x0507
	required uint32	result_code = 1;			//1: 失败 0:成功
	required uint32 from_user_id = 2;
	required uint32 to_user_id = 3;
	required string file_name = 4; 
	required string task_id = 5;  //传输任务的标示
	repeated IM.BaseDefine.IpAddr ip_addr_list = 6;   //用于文件传输的file_server 的ip以及port列表
	required IM.BaseDefine.TransferFileType trans_mode = 7;
}
~~~~

#### 2.检查自己是否有离线文件需要接收
##### 请求:IMFileHasOfflineReq

~~~~
//cmd id: 	CID_FILE_HAS_OFFLINE_REQ 0x0509
message IMFileHasOfflineReq{
	//cmd id: 	0x0509
	required uint32 user_id = 1;
	optional bytes attach_data = 20;
}
~~~~

#### 应答

~~~~
//cmd id: 	CID_FILE_HAS_OFFLINE_RSP 0x050a

message IMFileHasOfflineRsp{
	//cmd id:	0x050a
	required uint32 user_id = 1;
	repeated IM.BaseDefine.OfflineFileInfo offline_file_list = 2; //离线文件列表
	repeated IM.BaseDefine.IpAddr ip_addr_list = 3;   //file_server的ip与port
	optional bytes attach_data = 20;
}
~~~~


#### 3.生成一条离线任务的记录
得通知服务器写入数据库 对方上线后可以通过上面那个请求查询
##### 请求:IMFileAddOfflineReq
	

~~~~
//cmd id:	CID_FILE_ADD_OFFLINE_REQ 0x050b
message IMFileAddOfflineReq{
	//cmd id:	0x050b
	required uint32 from_user_id = 1;
	required uint32 to_user_id = 2;
	required string task_id = 3;
	required string file_name = 4;  
	required uint32 file_size = 5;
}
~~~~


#### 4.标记一条离线任务已被用户下载
下载完离线文件应该通知数据去修改这条记录的状态

~~~~
//cmd id: CID_FILE_DEL_OFFLINE_REQ 	0x050c
message IMFileDelOfflineReq{
	//cmd id:	0x050c
	required uint32 from_user_id = 1;
	required uint32 to_user_id = 2;
	required string task_id = 3;
}
~~~~



#### 5.验证用户(与file_server的交互)
##### 请求:IMFileLoginReq


~~~~
//cmd id:	CID_FILE_LOGIN_REQ 0x0501
message IMFileLoginReq{
	//cmd id:	0x0501
	required uint32 user_id = 1;
	required string task_id = 2;
	required IM.BaseDefine.ClientFileRole file_role= 3; //在线传输则是发送者或接收者 离线文件则分上传者跟下载者 
}
~~~~


##### 请求:IMFileLoginRsp


~~~~
//cmd id:	CID_FILE_LOGIN_RES 0x0502
	
message IMFileLoginRsp{
	//cmd id:	0x0502
	required uint32 result_code = 1;		//0:successed1:failed
	required string task_id = 2;
}
~~~~


#### 6.拉流(与file_server的交互)
##### 请求:IMFilePullDataReq
如果是离线文件，则又服务器发起。若是在线传输则由接收方发起(file_server充当中转的角色)

	
~~~~
//cmd id:CID_FILE_PULL_DATA_REQ	0x0504
message IMFilePullDataReq{
	//cmd id:	0x0504
	required string task_id = 1;
	required uint32 user_id = 2;
	required IM.BaseDefine.TransferFileType trans_mode = 3; //传输类型(在线或离线)
	required uint32 offset = 4; //文件偏移
	required uint32 data_size = 5;  //要读取的大小
}
~~~~


#### 应答:IMFilePullDataRsp

~~~~
message IMFilePullDataRsp{
	//cmd id: 	0x0505
	required uint32 result_code = 1; 
	required string task_id = 2;  
	required uint32 user_id = 3;
	required uint32 offset = 4;  //偏移位置
	required bytes file_data = 5;//文件数据
}
~~~~
