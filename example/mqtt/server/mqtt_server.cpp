#include <asio2/mqtt/mqtt_server.hpp>
#include <iostream>

int main()
{
#if defined(WIN32) || defined(_WIN32) || defined(_WIN64) || defined(_WINDOWS_)
	// Detected memory leaks on windows system
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

	std::string_view host = "0.0.0.0";
	std::string_view port = "1883";

	asio2::mqtt_server server;

	asio2::mqtt_options options;
	//mqtt::options options;

	server.set_options(options);

	server.bind_accept([](std::shared_ptr<asio2::mqtt_session>& session_ptr)
	{
		asio2::ignore_unused(session_ptr);

	}).bind_recv([](auto & session_ptr, std::string_view s)
	{
		asio2::ignore_unused(session_ptr, s);

		//printf("recv : %zu %.*s\n", s.size(), (int)s.size(), s.data());

		//session_ptr->async_send(std::string(s), [](std::size_t bytes_sent) {});

	}).bind_connect([](auto & session_ptr)
	{
		printf("client enter : %s %u %s %u\n", 
			session_ptr->remote_address().c_str(), session_ptr->remote_port(),
			session_ptr->local_address().c_str(), session_ptr->local_port());
		session_ptr->post([]() {}, std::chrono::seconds(3));
	}).bind_disconnect([](auto & session_ptr)
	{
		printf("client leave : %s %u %s\n", session_ptr->remote_address().c_str(),
			session_ptr->remote_port(), asio2::last_error_msg().c_str());
	}).bind_start([&]()
	{
		printf("start mqtt server : %s %u %d %s\n", 
			server.listen_address().c_str(), server.listen_port(),
			asio2::last_error_val(), asio2::last_error_msg().c_str());
	}).bind_stop([&]()
	{
		printf("stop : %d %s\n", asio2::last_error_val(), asio2::last_error_msg().c_str());
	});

	server.on_publish([](std::shared_ptr<asio2::mqtt_session>& session_ptr, mqtt::message& msg, mqtt::message& rep)
	{
		asio2::ignore_unused(session_ptr, msg, rep);
	});

	server.start(host, port);

	while (std::getchar() != '\n');

	return 0;
}
