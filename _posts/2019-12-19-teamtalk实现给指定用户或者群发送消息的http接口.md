---
layout: post
title:  teamtalk实现给指定用户或者群发送消息的http接口
date: 2019-12-19 18:26:48 +0800
author: xiaominfc
description: teamtalk拓展http_msg_server的接口
categories: teamtalk im
comments: true
---


# teamtalk实现给指定用户或者群发送消息的http接口




## 应用场景

1. 后台推送消息
2. 第三方对接接口
3. 系统消息


### 基本流程

只是说个大概 可以继续改进以便支持更好 用起来更方便

```

http_msg_server => db_proxy_server
db_proxy_server => http_msg_server
http_msg_server => router_server

原理很简单 只是把原来msg_server的角色换成了 http_msg_server 
过程一样 包装一个IMMsgData

```

### 实现(最简实现)

#### 1 http_msg_server复用加密操作

httpmsgserver.conf

```

# add aes_key
aesKey=12345678901234567890123456789012

```

http 请求 数据体通常是明文字符串或者其他 我们都得格式化成msg_server类似的格式 所以发送的消息内容是要加密的
所以上面我们饮用了类似的方式 配置加密密钥


#### 2 加密实例


file:http_msg_server.cpp

```

char* str_aes_key = config_file.GetConfigName("aesKey");
if (!str_aes_key || strlen(str_aes_key)!=32) {
	log("aes key is invalied");
	return -1;
}
pAes = new CAes(str_aes_key);

```

#### 3 声明


file:HttpQuery.h 

```

// add private methods to class CHttpQuery
	static void _SendMessage(const string& strAppKey,Json::Value& post_json_obj, CHttpConn* pHttpConn,int msg_type);
		static void _SendSingleMessage(const string& strAppKey,Json::Value& post_json_obj, CHttpConn* pHttpConn);
		static void _SendGroupMessage(const string& strAppKey,Json::Value& post_json_obj, CHttpConn* pHttpConn);

// add end


```

#### 4 实现

file:HttpQuery.cpp

```
void CHttpQuery::_SendMessage(const string& strAppKey,Json::Value& post_json_obj, CHttpConn* pHttpConn,int msg_type)
{
	HTTP::CDBServConn *pConn = HTTP::get_db_serv_conn();
	if (!pConn) {
		log("no connection to MsgServConn ");
		char* response_buf = PackSendResult(HTTP_ERROR_SERVER_EXCEPTION, HTTP_ERROR_MSG[9].c_str());
		pHttpConn->Send(response_buf, (uint32_t)strlen(response_buf));
		pHttpConn->Close();
		return;
	}

	if(checkValueIsNullForJson(post_json_obj, "from_user_id") ||
			checkValueIsNullForJson(post_json_obj, "session_id")   ||
			//checkValueIsNullForJson(post_json_obj, "create_time")  ||
			checkValueIsNullForJson(post_json_obj, "msg") ) {
		char* response_buf = PackSendResult(HTTP_ERROR_PARMENT, HTTP_ERROR_MSG[1].c_str());
		pHttpConn->Send(response_buf, (uint32_t)strlen(response_buf));
		pHttpConn->Close();
		return;
	}

	try
	{
		uint32_t user_id = post_json_obj["from_user_id"].asUInt();
		uint32_t to_id = post_json_obj["to_user_id"].asUInt();
		uint32_t create_time = time(NULL);
		string msgContent;
		if(post_json_obj["msg"].isString())
		{
			msgContent = post_json_obj["msg"].asString();
		}else if(post_json_obj["msg"].isObject())
		{
			msgContent = post_json_obj["msg"].toStyledString();
		}   
		char* msg_out = NULL;
		uint32_t msg_out_len = 0;
		if(pAes->Encrypt(msgContent.c_str(),msgContent.length(),&msg_out,msg_out_len) == 0)
		{
			msgContent = string(msg_out, msg_out_len);
		}
		pAes->Free(msg_out);

		CDbAttachData attach_data(ATTACH_TYPE_HANDLE, pHttpConn->GetConnHandle());
		IM::Message::IMMsgData msg;
		msg.set_from_user_id(user_id);
		msg.set_to_session_id(to_id);
		msg.set_msg_data(msgContent);
		msg.set_msg_id(1);
		msg.set_msg_type((IM::BaseDefine::MsgType)msg_type);
		msg.set_create_time(create_time);
		msg.set_attach_data(attach_data.GetBuffer(), attach_data.GetLength());
		CImPdu pdu;
		pdu.SetPBMsg(&msg);
		pdu.SetSeqNum(pHttpConn->GetConnHandle());
		pdu.SetServiceId(IM::BaseDefine::SID_MSG);
		pdu.SetCommandId(IM::BaseDefine::CID_MSG_DATA);
		pConn->SendPdu(&pdu);
	}
	catch (std::runtime_error msg)
	{
		log("parse json data failed.");
		char* response_buf = PackSendResult(HTTP_ERROR_PARMENT, HTTP_ERROR_MSG[1].c_str());
		pHttpConn->Send(response_buf, (uint32_t)strlen(response_buf));
		pHttpConn->Close();
	} 

}

void CHttpQuery::_SendSingleMessage(const string& strAppKey,Json::Value& post_json_obj, CHttpConn* pHttpConn)
{
	_SendMessage(strAppKey,post_json_obj,pHttpConn,IM::BaseDefine::MSG_TYPE_SINGLE_TEXT);
}



void CHttpQuery::_SendGroupMessage(const string& strAppKey,Json::Value& post_json_obj, CHttpConn* pHttpConn)
{
	_SendMessage(strAppKey,post_json_obj,pHttpConn,IM::BaseDefine::MSG_TYPE_GROUP_TEXT);
}


```

### 结语：具体实现可以看我github上维护的分支

[https://github.com/xiaominfc/TeamTalk](https://github.com/xiaominfc/TeamTalk)






