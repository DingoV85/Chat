//
// chat_message.hpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2019 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef CHAT_MESSAGE_HPP
#define CHAT_MESSAGE_HPP

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

class chat_message
{
public:
	enum { header_length = 4 };
	enum { autorization_flag_length = 6 }; // $auth$
	enum { login_length = 30 };
	enum { password_length = 20 };
	enum { helloMSG_length = 100 };
	enum { byeMSG_length = 100 };
	enum { max_body_length = 1000 };

	void print_message(char* msg, size_t size)
	{
		for (size_t i = 0; i < size; i++)
		{
			if (msg[i] == '\0')
			{
				std::cout << "|";
			}
			else std::cout << msg[i];
		}
		std::cout << std::endl;
	}


	chat_message()
		: body_length_(0)
	{
	}

	const char* data() const
	{
		return data_;
	}

	char* data()
	{
		return data_;
	}

	std::size_t length() const
	{
		return header_length + body_length_;
	}

	const char* body() const
	{
		return data_ + header_length;
	}

	const char* autorizeBody() const
	{
		return data_ + header_length + autorization_flag_length;
	}
	 
	const char* endBodyToken() const
	{
		return data_ + header_length + autorization_flag_length+login_length+password_length;
	}

	char* body()
	{
		return data_ + header_length;
	}

	std::size_t body_length_without_token() const
	{
		return body_length_ - login_length - password_length - header_length-2;
	}

	std::size_t body_length() const
	{
		return body_length_;
	}

	void body_length(std::size_t new_length)
	{
		body_length_ = new_length;
		if (body_length_ > max_body_length)
			body_length_ = max_body_length;
	}

	bool decode_header()
	{
		char header[header_length + 1] = "";
		strncat_s(header, data_, header_length);
		body_length_ = std::atoi(header);
		if (body_length_ > max_body_length)
		{
			body_length_ = 0;
			return false;
		}
		return true;
	}

	void autorization(std::string uLogin, std::string uPass, std::string uHello, std::string uBye)
	{
		char auth[autorization_flag_length + login_length + password_length + helloMSG_length + byeMSG_length + 1];
		memset(auth, '\0', sizeof(auth));
		std::string auth_token = "$auth$";
		std::string login = uLogin;
		std::string pass = uPass;
		std::string hello = uHello;
		std::string bye = uBye;

		memcpy(auth, auth_token.c_str(), auth_token.length());
		memcpy(auth + autorization_flag_length, login.c_str(), login.length());
		memcpy(auth + autorization_flag_length + login_length, pass.c_str(), pass.length());
		memcpy(auth + autorization_flag_length + login_length + password_length, hello.c_str(), hello.length());
		memcpy(auth + autorization_flag_length + login_length + password_length + helloMSG_length, bye.c_str(), bye.length());

		body_length(autorization_flag_length + login_length + password_length + helloMSG_length + bye.length());

		char header[header_length + 1] = "";
		const char* format = "%4d";
		int size = sizeof(header);
		std::snprintf(header, size, format, static_cast<int>(body_length_));

		std::memcpy(data_, header, header_length);
		std::memcpy(body(), auth, body_length_);
	}

	void readAutorizeMsg()
	{

	}

	void encode_header()
	{
		char header[header_length + 1] = "";
		int size = sizeof(header);
		std::snprintf(header, size, "%4d", static_cast<int>(body_length_));
		std::memcpy(data_, header, header_length);
	}

private:
	char data_[header_length + max_body_length];

	std::size_t body_length_;
};

#endif // CHAT_MESSAGE_HPP