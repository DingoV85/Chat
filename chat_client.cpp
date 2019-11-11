//
// chat_client.cpp
// ~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2019 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <cstdlib>
#include <deque>
#include <iostream>
#include <thread>
#include <boost/asio.hpp>
#include "c:/CHAT/chat_message.hpp"

using boost::asio::ip::tcp;

typedef std::deque<chat_message> chat_message_queue;

class chat_client
{
public:
	void chat_client_set_autorizMsg()
	{
		std::cout << "Enter Login: ";
		std::string login = "";
		std::getline(std::cin, login);
		//std::cout << std::endl;
		std::cout << "Enter password: ";
		std::string pass = "";
		std::getline(std::cin, pass);
		//std::cout << std::endl;
		std::string hello = "HELLO!";
		std::string bye = "BYE!";
		chat_message authMsg;
		authMsg.autorization(login, pass, hello, bye);
		autorizeMsg = authMsg;
	}


	chat_client(boost::asio::io_context& io_context,
		const tcp::resolver::results_type& endpoints/*, const chat_message& msg*/)
		: io_context_(io_context),
		socket_(io_context)//, autorizeMsg(msg)
	{
		chat_client_set_autorizMsg();
		//do_first_connect(endpoints);
		//bool do_autor = do_autorize();
		bool do_autor = true;
		//std::cout << "do_autorize():  " << do_autor << std::endl;
		if (do_autor)
		{
			std::cout << "You autorize on server!!!" << std::endl;
			do_connect(endpoints);
		}
		else
		{
			std::cout << "You don't autorize on server!!!" << std::endl;
		}
	}


	chat_message addTokenToMsg(chat_message msg)
	{
		chat_message msg2;
		char tokMsg[msg2.autorization_flag_length + msg2.max_body_length + msg2.login_length + msg2.password_length+ 1];
		msg2.body_length(msg.body_length() + msg2.autorization_flag_length + msg2.login_length + msg2.password_length);

		memset(tokMsg, '\0', sizeof(tokMsg));
		std::string token = "token$" + this->token;
		std::memcpy(tokMsg, token.c_str(), token.length());
		std::memcpy(tokMsg + msg.autorization_flag_length + msg.login_length + msg.password_length, msg.body(), msg.body_length());

		char header[msg2.header_length + 1] = "";
		const char* format = "%4d";
		int size = sizeof(header);
		std::snprintf(header, size, format, static_cast<int>(msg2.body_length()));

		std::memcpy(msg2.data(), header, msg2.header_length);
		std::memcpy(msg2.body(), tokMsg, msg2.body_length());

		return msg2;
	}

	void write(chat_message& msg)
	{
		boost::asio::post(io_context_,
			[this, msg]()
			{
	//			std::cout << "write(msg) lambda" << std::endl;
				bool write_in_progress = !write_msgs_.empty();
				write_msgs_.push_back(msg);
				if (!write_in_progress)
				{
					do_write();
				}
			});
	}

	void close()
	{
		boost::asio::post(io_context_, [this]() { socket_.close(); });
	}

private:
	bool do_autorize()
	{
	//	std::cout << "do_autorize()" << std::endl;

		bool resultAutorize = false;
		//autorizeMsg.print_message(autorizeMsg.data(), autorizeMsg.length());
		boost::asio::async_write(socket_,
				boost::asio::buffer(autorizeMsg.data(),
					autorizeMsg.length()),
				[this,&resultAutorize](boost::system::error_code ec, std::size_t /*length*/)
				{
				std::cout << ec << std::endl;
	//			std::cout << "do_autorize lambda" << std::endl;
				    if (!ec)
					{
	//					std::cout << "AUTORIZE send" << std::endl;
						resultAutorize = true;
					}
					else
					{
						socket_.close();
					}
				});
		
	//	std::cout << "resultAutorize = "<< resultAutorize << std::endl;
		return resultAutorize;

	}
	

	void do_first_connect(const tcp::resolver::results_type& endpoints)
	{
	//	std::cout << "do_first_connect(endpoints)" << std::endl;
		//std::cout << "socet_is_open?" << socket_.is_open() << std::endl;
		boost::asio::async_connect(socket_, endpoints,
			[this](boost::system::error_code ec, tcp::endpoint)
			{
				std::cout << ec<<"ec err " << std::endl;

				if (!ec)
				{
		//			std::cout << "do_first_connect(endpoints) lambda" << std::endl;
					//do_read_header();
				}
			});
	}

	void do_connect(const tcp::resolver::results_type& endpoints)
	{
		//std::cout << "do_connect(endpoints)" << std::endl;
		//std::cout << "socet_is_open?" <<socket_.is_open() << std::endl;
		boost::asio::async_connect(socket_, endpoints,
			[this](boost::system::error_code ec, tcp::endpoint)
			{
		//		std::cout << ec << " ec  err  do_conect()"<<std::endl;
				if (!ec)
				{
					
					bool resultAut = do_autorize();
		//			std::cout<<"connect do_autorize();"<<resultAut<<std::endl;
		//			std::cout << "do_read_header();" << std::endl;
					do_read_header();
				}
			});
	}


	void do_read_header()
	{
	//	std::cout << "do_read_header()" << std::endl;

		boost::asio::async_read(socket_,
			boost::asio::buffer(read_msg_.data(), chat_message::header_length),
			[this](boost::system::error_code ec, std::size_t /*length*/)
			{
	//			std::cout << ec<<" ec err do_read_header()" << std::endl;

				if (!ec && read_msg_.decode_header())
				{
					do_read_body();

				}
				else
				{
					socket_.close();
				}
			});
	}

	std::string selectionOfAPart(chat_message& msg, int end)
	{
		std::string result = "";
		for (size_t i = 0; i < end; i++)
		{
			if (*(msg.body() + i) != '\0')
			{
				result += *(msg.body() + i);
			}
		}

		//std::cout << std::endl << "result: " << result << std::endl;
		return result;
	}

	std::string selectionOfAPart(chat_message& msg,int begin, int end)
	{
		std::string result = "";
		for (size_t i = begin; i < end; i++)
		{
			if (*(msg.body() + i) != '\0')
			{
				result += *(msg.body() + i);
			}
		}

		//std::cout << std::endl << "result: " << result << std::endl;
		return result;
	}

	void do_read_body()
	{
	//	std::cout << "do_read_boady()" << std::endl;

		boost::asio::async_read(socket_,
			boost::asio::buffer(read_msg_.body(), read_msg_.body_length()),
			[this](boost::system::error_code ec, std::size_t /*length*/)
			{
				
				if (!ec)
				{
					
					
					//std::cout << "Length msg = " << read_msg_.body_length() << std::endl;
					std::string isTok = selectionOfAPart(read_msg_, read_msg_.autorization_flag_length);
					//std::cout << std::endl << "isTok :" << isTok << std::endl;
					if (isTok == "token$")
					{
						std::string tok = selectionOfAPart(read_msg_, read_msg_.autorization_flag_length, read_msg_.body_length());
						this->token=tok;
					}
					else
					{
					std::cout.write(read_msg_.body(), read_msg_.body_length());
					std::cout << "\n";

					}
					do_read_header();
				}
				else
				{
					socket_.close();
				}
			});
	}

	void do_write()
	{
	//	std::cout << "do_write()" << std::endl;

		boost::asio::async_write(socket_,
			boost::asio::buffer(write_msgs_.front().data(),
				write_msgs_.front().length()),
			[this](boost::system::error_code ec, std::size_t /*length*/)
			{
				if (!ec)
				{
		//			std::cout << "do_write() lamda" << std::endl;

					write_msgs_.pop_front();
					if (!write_msgs_.empty())
					{
						do_write();
					}
				}
				else
				{
					socket_.close();
				}
			});
	}

private:
	boost::asio::io_context& io_context_;
	tcp::socket socket_;
	chat_message read_msg_;
	chat_message autorizeMsg;
	chat_message_queue write_msgs_;
	std::string token;
};

int main(int argc, char* argv[])
{
	try
	{
		if (argc != 3)
		{
			std::cerr << "Usage: chat_client <host> <port>\n";
			return 1;
		}
		
		
		boost::asio::io_context io_context;

		tcp::resolver resolver(io_context);
		auto endpoints = resolver.resolve(argv[1], argv[2]);
		chat_client c(io_context, endpoints);

		std::thread t([&io_context]() { io_context.run(); });

		char line[chat_message::max_body_length + 1];

		while (std::cin.getline(line, chat_message::max_body_length + 1))
		{
			chat_message msg;
			msg.body_length(std::strlen(line));
			std::memcpy(msg.body(), line, msg.body_length());
			msg = c.addTokenToMsg(msg);
			msg.encode_header();
			c.write(msg);
		}

		c.close();
		t.join();
	}
	catch (std::exception & e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}