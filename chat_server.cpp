//
// chat_server.cpp
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
#include <list>
#include <memory>
#include <map>
#include <set>
#include <utility>
#include <boost/asio.hpp>
#include "c:/CHAT/chat_message.hpp"

using boost::asio::ip::tcp;

//----------------------------------------------------------------------

typedef std::deque<chat_message> chat_message_queue;

//----------------------------------------------------------------------

class chat_participant
{
public:
	virtual ~chat_participant() {}
	virtual void deliver(const chat_message& msg) = 0;

	void setLogit(std::string log)
	{
		this->login = log;
	}

	void setPass(std::string pass)
	{
		this->password = pass;
	}
	void setToken(std::string tok)
	{
		this->token = tok;
	}
	void setByeMsg(std::string bye)
	{
		this->byeMsg = bye;
	}

	std::string getBye()
	{
		return this->byeMsg;
	}

	std::string getlogin()
	{
		return this->login;
	}

	std::string getToken()
	{
		return this->token;
	}


private:
	std::string login;
	std::string password;
	std::string byeMsg;
	std::string token;

};

typedef std::shared_ptr<chat_participant> chat_participant_ptr;

//----------------------------------------------------------------------

struct autorize_participant
{
	autorize_participant(std::string pass, std::string hello, std::string bye) : passw(pass), hello_msg(hello), bye_msg(bye)
	{};
	
	std::string passw;
	std::string hello_msg;
	std::string bye_msg;

};

class chat_room
{
public:
	void join(chat_participant_ptr participant)
	{
		participants_.insert(participant);
		std::cout << "join participant" << std::endl;
		/*for (auto msg : recent_msgs_)
			participant->deliver(msg);*/
	}

	void sendAllMsg(chat_participant_ptr participant)
	{
		for (auto msg : recent_msgs_)
			participant->deliver(msg);
	}

	void newRegistration(std::string log, std::string pass, std::string hello, std::string bye)
	{
		autorize_participant auth_patricipant(pass, hello, bye);
		participant_auth_inf.insert(std::pair<std::string, autorize_participant>(log, auth_patricipant));
		//this->participant
	}

	bool findChekCoincidence(std::string log, std::string pass)
	{
		//std::map<std::string, autorize_participant>
		bool result = true;
		std::map<std::string, autorize_participant>::iterator it = participant_auth_inf.find(log);
		if (it != participant_auth_inf.end())
		{
			if (it->second.passw != pass)
			{
				result = false;
			};

		}
		return result;
	}


	void leave(chat_participant_ptr participant, chat_room & room)
	{
		std::string bye = participant->getBye();
		std::string log = participant->getlogin();
		participants_.erase(participant);
		chat_message msg;
		
		std::cout << "bye.length() " << bye.length() << std::endl;
		if (bye.length())
		{
		log += ": ";

		char auth[msg.byeMSG_length + msg.login_length + 1];
		msg.body_length(bye.length() +  log.length());
		memset(auth, '\0', sizeof(auth));
		std::cout << "log" << log << std::endl;
		std::memcpy(auth, log.c_str(), log.length());
		std::memcpy((auth + log.length()), bye.c_str(), bye.length());
		
		char header[msg.header_length + 1] = "";
		const char* format = "%4d";
		int size = sizeof(header);
		std::snprintf(header, size, format, static_cast<int>(msg.body_length()));

		std::memcpy(msg.data(), header, msg.header_length);
		std::memcpy(msg.body(), auth, msg.body_length());
		room.deliver(msg);                              ///////////////send bye message

		}
		//std::cout << "leave participant" << std::endl;
	}

	void deliver(const chat_message & msg)
	{
		std::cout << "deliver() chat_room" << std::endl;
		recent_msgs_.push_back(msg);
		while (recent_msgs_.size() > max_recent_msgs)
			recent_msgs_.pop_front();

		for (auto participant : participants_)
			participant->deliver(msg);
	}

private:
	std::set<chat_participant_ptr> participants_;
	std::map<std::string, autorize_participant> participant_auth_inf;
	enum { max_recent_msgs = 100 };
	chat_message_queue recent_msgs_;
};

//----------------------------------------------------------------------

class chat_session
	: public chat_participant,
	public std::enable_shared_from_this<chat_session>
{
public:
	chat_session(tcp::socket socket, chat_room& room)
		: socket_(std::move(socket)),
		room_(room)
	{
	}

	void start()
	{
		std::cout << "start()  chat_session" << std::endl;

		room_.join(shared_from_this());
		do_read_header();
	}

	void deliver(const chat_message& msg)
	{
		std::cout << "deliver(msg)   chat_session" << std::endl;
		bool write_in_progress = !write_msgs_.empty();
		write_msgs_.push_back(msg);
		if (!write_in_progress)
		{
			do_write();
		}
	}
	
	std::string getLogin() 
	{
		return this->loginParticipant;
	}


	std::string getBye()
	{
		return this->byeParticipant;
	}

private:
	void do_read_header()
	{
		std::cout << "do_read_header() chat_session" << std::endl;
		auto self(shared_from_this());
		boost::asio::async_read(socket_,
			boost::asio::buffer(read_msg_.data(), chat_message::header_length),
			[this, self](boost::system::error_code ec, std::size_t /*length*/)
			{
				if (!ec && read_msg_.decode_header())
				{
					do_read_body();
				}
				else
				{
					room_.leave(shared_from_this(), room_);
				}
			});
	}

	chat_message authorize_participant(chat_message& mes)
	{

	}

	int isAuthorizationMessage(chat_message& msg)
	{

		int result = 0;
		std::string auth = "$auth$";
		std::string tok = "token$";
		std::string results = "";
		for (size_t i = 0; i < msg.autorization_flag_length; i++)
		{
			results += *(msg.body()+i);
			//std::cout << "results: " << results << std::endl;
		}

		std::cout << "results: " << results << std::endl;
		if (results == auth)
		{
			result = 1;
		}
		else if (results == tok)
		{
			result = 2;
		}
		return result;
	}

	std::string selectionOfAPart(chat_message& msg, int begin, int end)
	{
		std::string result = "";
		for (size_t i = begin; i < end; i++)
		{
			if (*(msg.body() + i) != '\0')
			{
				result += *(msg.body() + i);
			}
		}

		//std::cout  << std::endl << "result: "<<result << std::endl;
		return result;
	}

	chat_message pars_msg_for_auth(chat_message& msg, chat_participant_ptr participant)
	{
		std::string login = selectionOfAPart(msg, msg.autorization_flag_length , msg.autorization_flag_length + msg.login_length);
		//std::cout << "login = " << login<<"login_end" << std::endl;
		this->loginParticipant =login;

		std::string password = selectionOfAPart(msg, msg.autorization_flag_length + msg.login_length, msg.autorization_flag_length + msg.login_length+msg.password_length);
		//std::cout << "password = " << password << std::endl;
		this->passwordParticipant=password;

		std::string hello = selectionOfAPart(msg, msg.autorization_flag_length + msg.login_length+msg.password_length, msg.autorization_flag_length + msg.login_length+msg.password_length +msg.helloMSG_length);
		//std::cout << "hello = " << hello << std::endl;
		
		std::string bye = selectionOfAPart(msg, msg.autorization_flag_length + msg.login_length + msg.password_length + msg.helloMSG_length, msg.body_length());
		//std::cout << "bye = length   " << bye.length()<<bye << std::endl;
		//this->byeParticipant= bye;
		participant->setLogit (login);
		participant->setPass (password);
		participant->setByeMsg (bye);
		
		room_.newRegistration( login, password, hello, bye);

		///////////////////////////////////////////////////////////////////////////////////
		
		chat_message msg2;
		char auth[msg2.helloMSG_length + msg2.login_length + 1];
		std::string log = login + ": ";
		msg2.body_length(hello.length()+log.length());

		memset(auth, '\0', sizeof(auth));
		std::memcpy(auth, log.c_str(), log.length());
		std::memcpy((auth+log.length()), hello.c_str(), hello.length());

		char header[msg2.header_length + 1] = "";
		const char* format = "%4d";
		int size = sizeof(header);
		std::snprintf(header, size, format, static_cast<int>(msg2.body_length()));

		std::memcpy(msg2.data(), header, msg2.header_length);
		std::memcpy(msg2.body(), auth, msg2.body_length());

		return msg2;
		////////////////////////////////////////////////////////////////////////////////////
	}

	chat_message authorize_participant_by_token(chat_message& msg)
	{
		/*std::cout << "print first msg with token" << std::endl;
		msg.print_message(msg.data(), msg.body_length());*/
		chat_message msg2;
		
		char auth[msg2.max_body_length + msg2.login_length  + 1];
		
		std::string log = this->loginParticipant + ": ";
		msg2.body_length(msg.body_length()+log.length());    /////all length arrey char

		memset(auth, '\0', sizeof(auth));
		//std::cout << "log" << log << std::endl;
		std::memcpy(auth, log.c_str(), log.length());
		std::memcpy((auth + log.length()), msg.endBodyToken(), msg.body_length_without_token());

		char header[msg2.header_length + 1] = "";
		const char* format = "%4d";
		int size = sizeof(header);
		std::snprintf(header, size, format, static_cast<int>(msg2.body_length()));

		std::memcpy(msg2.data(), header, msg2.header_length);
		std::memcpy(msg2.body(), auth, msg2.body_length());

		/*std::cout << "print msg without token" << std::endl;
		msg.print_message(msg.data(), msg.max_body_length);*/

		return msg2;
	}

	chat_message generateToken(chat_participant_ptr participant)
	{
		chat_message token;
		std::string genTok = this->loginParticipant + this->passwordParticipant;
		this->token = genTok;
		participant->setToken(genTok);
		token.body_length(genTok.length()+ token.autorization_flag_length);
		char tok[token.autorization_flag_length + token.login_length + token.password_length + 1];
		memset(tok, '\0', sizeof(tok));

		std::memcpy(tok, "token$", token.autorization_flag_length);
		std::memcpy(tok + token.autorization_flag_length, genTok.c_str(), genTok.length());
		char header[token.header_length + 1] = "";
		const char* format = "%4d";
		int size = sizeof(header);
		std::snprintf(header, size, format, static_cast<int>(token.body_length()));

		std::memcpy(token.data(), header, token.header_length);
		std::memcpy(token.body(), tok, token.body_length());
		//token.print_message(token.body(), token.body_length());
		//////////////////////////////////////////////////////////////////////////////////////////////
		return token;
	}
		
	chat_message authorize_participant_bye_msg(chat_message& msg)
	{
		chat_message msg2;
		//msg.print_message(msg.data(), msg.max_body_length);

		char auth[msg2.byeMSG_length + msg2.login_length + 1];

		msg2.body_length(this->byeParticipant.length() + this->loginParticipant.length() + 2);

		memset(auth, '\0', sizeof(auth));
		std::string log = this->loginParticipant + ": ";
		//std::cout << "log" << log << std::endl;
		std::memcpy(auth, log.c_str(), log.length());
		std::memcpy((auth + log.length()), this->byeParticipant.c_str(), this->byeParticipant.length());

		char header[msg2.header_length + 1] = "";
		const char* format = "%4d";
		int size = sizeof(header);
		std::snprintf(header, size, format, static_cast<int>(msg2.body_length()));

		std::memcpy(msg2.data(), header, msg2.header_length);
		std::memcpy(msg2.body(), auth, msg2.body_length());

		return msg2;
	}

	void do_read_body()
	{
		std::cout << "do_read_body() chat_session" << std::endl;
		auto self(shared_from_this());
		boost::asio::async_read(socket_,
			boost::asio::buffer(read_msg_.body(), read_msg_.body_length()),
			[this, self](boost::system::error_code ec, std::size_t /*length*/)
			{
				if (!ec)
				{
					auto body = read_msg_.body_length();
					bool isAuthMsg = body >= read_msg_.autorization_flag_length;
					auto isAutorizMsg = isAuthorizationMessage(read_msg_);
					//read_msg_.print_message(read_msg_.data(), read_msg_.body_length());
					if (isAuthMsg && isAutorizMsg == 1)
					{
						std::string login = selectionOfAPart(read_msg_, read_msg_.autorization_flag_length, read_msg_.autorization_flag_length + read_msg_.login_length);
						std::string password = selectionOfAPart(read_msg_, read_msg_.autorization_flag_length + read_msg_.login_length, read_msg_.autorization_flag_length + read_msg_.login_length + read_msg_.password_length);
											
						if (room_.findChekCoincidence(login, password))
						{
							room_.sendAllMsg(shared_from_this());
							chat_message read_msg_auth = pars_msg_for_auth(read_msg_, shared_from_this());
							//read_msg_auth.print_message(read_msg_auth.data(), read_msg_auth.body_length());
							//room_.newRegistration(self, log, pass, hello, bye);
							//std::cout << "this->getLogin()"<<this->getLogin() <<std::endl;
							room_.deliver(read_msg_auth);
							chat_message token = generateToken(shared_from_this());
							//token.print_message(token.data(), token.length());
							shared_from_this()->deliver(token);
							do_read_header();
						}
						else 
						{
							room_.leave(shared_from_this(), room_);
						}
					//authorize_participant();
					}
					else if (isAuthMsg && isAutorizMsg == 2)
					{
						std::string tok = selectionOfAPart(read_msg_, read_msg_.autorization_flag_length, read_msg_.autorization_flag_length + read_msg_.login_length+ read_msg_.password_length);
						std::cout << "tok =" << tok << std::endl;
						if (shared_from_this()->token == tok)
						{
							chat_message msg_send = authorize_participant_by_token(read_msg_);

							room_.deliver(msg_send);
							do_read_header();
						}
						else 
						{
							room_.leave(shared_from_this(), room_);
						}
					}
					else {
						//read_msg_.print_message(read_msg_.data(), read_msg_.max_body_length);
						//room_.deliver(authorize_participant_by_token(read_msg_));
						//do_read_header();
						room_.leave(shared_from_this(), room_);
					}
				}

				else
				{
					//    room_.deliver(read_msg_);      
					//chat_message nnn = authorize_participant_bye_msg(read_msg_);
					//read_msg_.print_message(nnn.data(), nnn.max_body_length);
					room_.leave(shared_from_this(),room_);
					//room_.deliver(authorize_participant_bye_msg(read_msg_));
				}
			});
	}


void do_write()
{
	//std::cout << "do_write() chat_session" << std::endl;
	auto self(shared_from_this());
	std::cout << "write_msgs_.front().print_message" << std::endl;
	write_msgs_.front().print_message(write_msgs_.front().data(), write_msgs_.front().body_length()+4);
	boost::asio::async_write(socket_,
		boost::asio::buffer(write_msgs_.front().data(),
			write_msgs_.front().length()),
		[this, self](boost::system::error_code ec, std::size_t /*length*/)
		{
			if (!ec)
			{
				//std::cout << "do_write() lambda chat_session" << std::endl;
				write_msgs_.pop_front();
				if (!write_msgs_.empty())
				{

					do_write();
				}
			}
			else
			{
				room_.leave(shared_from_this(),room_);
			}
		});
}

tcp::socket socket_;
chat_room& room_;
chat_message read_msg_;
chat_message_queue write_msgs_;
std::string loginParticipant;
std::string token;
std::string passwordParticipant;
std::string byeParticipant;
};

//----------------------------------------------------------------------

class chat_server
{
public:
	chat_server(boost::asio::io_context& io_context,
		const tcp::endpoint& endpoint)
		: acceptor_(io_context, endpoint)
	{
		do_accept();
	}

private:
	void do_accept()
	{
		std::cout << "do_accept() chat_server" << std::endl;
		acceptor_.async_accept(
			[this](boost::system::error_code ec, tcp::socket socket)
			{
				std::cout << "ec err " << ec << std::endl;
				if (!ec)
				{
					std::make_shared<chat_session>(std::move(socket), room_)->start();
				}

				do_accept();
			});
	}

	tcp::acceptor acceptor_;
	chat_room room_;
};

//----------------------------------------------------------------------

int main(int argc, char* argv[])
{
	try
	{
		if (argc < 2)
		{
			std::cerr << "Usage: chat_server <port> [<port> ...]\n";
			return 1;
		}

		boost::asio::io_context io_context;

		std::list<chat_server> servers;
		for (int i = 1; i < argc; ++i)
		{
			tcp::endpoint endpoint(tcp::v4(), std::atoi(argv[i]));
			servers.emplace_back(io_context, endpoint);
		}

		io_context.run();
	}
	catch (std::exception & e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}