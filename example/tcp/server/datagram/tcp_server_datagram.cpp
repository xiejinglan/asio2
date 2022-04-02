//#include <asio2/asio2.hpp>
#include <iostream>
#include <asio2/tcp/tcp_server.hpp>
#include <asio2/util/uuid.hpp>

int main()
{
#if defined(WIN32) || defined(_WIN32) || defined(_WIN64) || defined(_WINDOWS_)
	// Detected memory leaks on windows system
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

	std::string_view host = "0.0.0.0";
	std::string_view port = "8027";

	std::srand((unsigned int)time(nullptr));

	// Specify the "max recv buffer size" to avoid malicious packets, if some client
	// sent data packets size is too long to the "max recv buffer size", then the
	// client will be disconnect automatic .
	asio2::tcp_server server(
		512,  // the initialize recv buffer size : 
		1024, // the max recv buffer size :
		4     // the thread count : 
	);

	server.bind_recv([&](auto & session_ptr, std::string_view s)
	{
		printf("recv : %u %.*s\n", (unsigned)s.size(), (int)s.size(), s.data());

		std::string uuid = asio2::uuid().next().str();

		std::string msg{ s };

		session_ptr->start_timer(uuid, std::chrono::milliseconds(std::rand() % 999), [uuid, session_ptr, msg]()
		{
			session_ptr->stop_timer(uuid);
			session_ptr->async_send(msg);
		});

		//session_ptr->async_send(s, [](std::size_t bytes_sent) {std::ignore = bytes_sent; });

	}).bind_connect([&](auto & session_ptr)
	{
		session_ptr->no_delay(true);

		//session_ptr->stop(); // You can close the connection directly here.

		printf("client enter : %s %u %s %u\n",
			session_ptr->remote_address().c_str(), session_ptr->remote_port(),
			session_ptr->local_address().c_str(), session_ptr->local_port());

	}).bind_disconnect([&](auto & session_ptr)
	{
		printf("client leave : %s %u %s\n",
			session_ptr->remote_address().c_str(),
			session_ptr->remote_port(), asio2::last_error_msg().c_str());
	}).bind_start([&]()
	{
		printf("start tcp server dgram : %s %u %d %s\n",
			server.listen_address().c_str(), server.listen_port(),
			asio2::last_error_val(), asio2::last_error_msg().c_str());
	}).bind_stop([&]()
	{
		printf("stop : %d %s\n", asio2::last_error_val(), asio2::last_error_msg().c_str());
	});

	server.start(host, port, asio2::use_dgram); // dgram tcp

	while (std::getchar() != '\n');

	server.stop();

	return 0;
}
