#include "common.h"

int main(int argc, char **argv)
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
	if(argc < 3) {
		daemonize();
	}
	signal(SIGPIPE, SIG_IGN);

	ret = log_init(HADM_LOG_CONF, HADM_SERVER_LOG_CAT);
	if(ret < 0) {
		exit(EXIT_FAILURE);
	}

	cfg = load_config(CONFIG_FILE);
	if(cfg == NULL) {
		log_error("load config file failed, please check config file!");
		exit(EXIT_FAILURE);
	}

	daemon = create_daemon(cfg);
	if(daemon == NULL) {
		exit(EXIT_FAILURE);
	}

	if(init_daemon(daemon) < 0) {
		exit(EXIT_FAILURE);
	}

	daemon_run(daemon);

	return 0;
}
