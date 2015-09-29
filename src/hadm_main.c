#include "common.h"

int main()
{
	struct daemon *daemon;
	struct config *cfg;
	int ret;

	/*
	   if(!check_root()) {
	   fprintf(stderr, "permission denied, root only\n");
	   exit(EXIT_FAILURE);
	   }
	 */

	daemonize();
	signal(SIGPIPE, SIG_IGN);

	ret = log_init(HADM_LOG_CONF, HADM_SERVER_LOG_CAT);
	if(ret < 0) {
		exit(EXIT_FAILURE);
	}
	log_info("init log done");

	cfg = load_config(CONFIG_FILE);
	if(cfg == NULL) {
		log_error("load config file failed, please check config file!");
		exit(EXIT_FAILURE);
	}
	pr_config(cfg);
	log_info("init config done");

	daemon = create_daemon(cfg);
	if(daemon == NULL) {
		exit(EXIT_FAILURE);
	}
	log_info("create daemon done");

	if(init_daemon(daemon) < 0) {
		exit(EXIT_FAILURE);
	}
	log_info("init daemon done");

	daemon_run(daemon);

	return 0;
}
