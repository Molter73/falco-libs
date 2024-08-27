#include "../../event_class/event_class.h"

#ifdef __NR_recvmmsg
TEST(SyscallEnter, recvmmsgE) {
	auto evt_test = get_syscall_event_test(__NR_recvmmsg, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	int32_t mock_fd = -1;
	struct msghdr *msg = NULL;
	uint32_t vlen = 0;
	int flags = 0;
	struct timespec *timeout = NULL;
	assert_syscall_state(SYSCALL_FAILURE,
	                     "recvmmsg",
	                     syscall(__NR_recvmmsg, mock_fd, msg, vlen, flags, timeout));

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	evt_test->assert_numeric_param(1, (int64_t)mock_fd);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(1);
}
#endif
