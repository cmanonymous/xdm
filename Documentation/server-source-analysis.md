
# daemon{}

## 在 create_daemon() 中设置的内容

node_list = init_node_list()
dev = init_device()
local_node
local_handler = local_handler

### local_handler 在哪里启动运行？为什么要有这个 local_handler？没有它会怎么样？
    没有它行不行？

local_handler() 是一个回调函数，它在 daemon->local_fd 监听端口有新的连接进来的时
候被调用。

当 local_handler() 被调用的时候，说明已经有连接被建立了。这个连接是内核模块到
daemon 的连接，内核模块要建立两个到 daemon 的连接，一个是数据链路，一个控制链路。

这个函数接下来会从内核模块中接收用户层的握手包 P_KERN_HANDSHAKE_{D,M}，然后会发
送对应的应答包 P_KERN_HANDSHAKE_{D,M}_ACK 到内核模块。握手过程完成后，daemon 就
设置好了 dev->dfd/dev->mfd 和它们相应的事件处理函数，即是 dev->data_handler 和
dev->meta_handler。

### node_data_handler 在哪里启动运行？为什么要有这个 node_data_handler？没有它会
    怎么样？没有它行不行？

node_data_handler() 是一个回调函数，它在所有节点的连接都建立以后，在
connect_function() 中调用 node_add_data_event() 调用的。这个回调函数由 libevent
在发生指定事件的时候调用，在这里是描述父可读。这个回调函数所做的事情就是把收到的
数据包挂入 node->work_q 队列中。如果没有它的话，那么收到的数据包就得不到处理了。
所以，没有它是不行的。

### node_meta_handler 在哪里启动运行？为什么要有这个 node_meta_handler？没有它会
    怎么样？没有它行不行？

和 node_data_handler() 一样，这是一个回调函数，它在所有节点的连接建立之后设置。
它由 libevent 负责在发生指定的事件后调用，在这里也是描述父可读。这个回调函数所做
的事情是把接收到的 meta 数据包挂入节点的 node->work_q 队列中。如果没有这个回调函
数，就没有接收 meta 数据包的地方了，所以 meta 数据包将得不到处理。因此，没有它是
不行的。

## 在 init_daemon() 中设置的内容

初始化 libevent 事件，初始化 timer_base

local_fd = make_server()
connect_thread call connect_function()

local_event(EV_READ|EV_PERSIST) = local_fd, local_handler
event_base

## timer_base{}

timer_base 有什么作用？

timer_base 应该是一个定时器管理者，是为了方便而自定义的一个东西。如果没有它的话，
那么定时器就可能散落在各个地方，不方便维护。

timer_thread call timer_function()
connect_timer connect_timer_cb(tb)
kmod_check_timer kmod_check_timer_cb(tb)

### timer_function() 是做什么的？为什么要有它？没有它会怎么样？

这个函数用户启动 timer_base 定义的定时器。由于 daemon 需要定时完成检查内核模块是
否已经卸载、检查所有节点是否已经连接同时通知 daemon 所有节点的连接状态、检查每个
节点是否已经断开。由于 timer_base 可以看作是对所有定时器的管理者，因此这个函数就
是启动这些定时器，daemon 需要定时的任务都往这里添加，特别是检查所有节点的连接。
因此，不能删除这个函数。

## libevent function

### libevent 的使用方法

1. 初始化 event_base 结构体
2. 初始化 event 结构体
3. 添加事件
4. 分发、运行事件

### event_base_new()

创建一个 event_base，可以理解为一个事件集合的管理集合。

### event_new()

创建一个事件。

### event_add()

把事件加入到 event_base 以备调度。

### event_base_dispatch()

开始事件处理循环，这个函数运行之后，发生了事件之后，就会调用绑定到事件的处理函数
了。

### evtimer_new()

创建一个定时器。

### evtimer_add()

将定时器加入到 event_base 中。

# daemon_run()

所有节点的连接建立之后，需要设置每个节点接收到数据包的回调函数，还要加入一个
ping_timer 定时器。

# node_list{}

node_list 是一个指针数组，最多支持 32 个节点。每个节点指针指向一个 node 结构。

# node{}

node 结构是由 make_node() 创建的。

data_worker call node_data_worker_function
meta_worker call node_meta_worker_function
worker      call node_worker_function

data_q/meta_q/work_q

node_data_worker_function() 从 node->data_q 中取得数据，发送到对端节点中。

node_meta_worker_function() 从 node->meta_q 中取得要数据包，发送到对端节点中。

node_worker_function() 做的事情就是从 node->work_q 中取得数据，根据包的类型把这
个包放到对应的设备当中。比如，data 类型的包放到 dev->data_q，而 meta 类型的包放
到 dev->meta_q 中。

对于 meta 类型的包，目前有两种类型的包有不同的处理，也就是不加到设备的队列中，这
两种包的类型是 P_{SC,NC}_PING 和 P_{SC,NC}_PING_ACK。对于 P_{SC,NC}_PING 来说，它的处理函
数是 w_node_meta_ping_action()，它将会构造一个 P_{SC,NC}_PING_ACK 的包，挂入对应节
点的 meta_q 队列中；也就是说，如果从节点 1 中收到一个 P_{SC,NC}_PING 的包，那么这个
函数将会返回一个 P_{SC,NC}_PING_ACK 的包给节点 1。

对于 P_{SC,NC}_PING_ACK 的包，则只是减少一次节点检测的次数(--node->ping_count)。

## node 的 data_q/meta_q/work_q 的数据从哪里来？

data_q/meta_q 的数据由 device_worker_function() 挂入节点的队列中。

数据的流向从 dev->work_q 到 node->data_q/node->meta_q

node->work_q 的数据由 node_data_handler() 和 node_meta_handler() 从对端节点接收
后，挂入到这个队列中。

# device{}

## 在 make_device() 中设置的内容

data_handler = kern_data_handler
meta_handler = kern_meta_handler

data_worker = device_data_worker_function
meta_worker = device_meta_worker_function
worker	    = device_worker_function

data_q/meta_q/work_q

device_worker_function() 从 dev->work_q 队列中得到一个数据，然后根据包的类型，选
择不同的处理函数。对于 data 类型的包，它的处理函数是w_dev_data_common_action()，
这个函数将会根据要发送到的节点，克隆这个包挂入相应节点的 data_q 队列中。也就是说，
要发送到 3 个节点，就要克隆 3 个包挂入相应节点的队列中。

device_data_worker_function() 从 dev->data_q 中取得数据，发送到内核模块中。

device_meta_worker_function() 从 dev->meta_q 中取得数据，发送到内核模块中。

## device 的 data_q/meta_q/work_q 的队列数据从哪里来？

device 的 data_q/meta_q 队列的数据由 node_worker_function() 挂入其中。数据的流向
是从 node->work_q 到 dev->data_q 和 data->meta_q。

device 的 work_q 队列的数据由 kern_data_handler()/kern_meta_handler() 从内核模块
中接收数据并挂入其中。数据的流向是从内核模块到 dev->work_q。

# 从本地节点到对端节点的数据流向是怎样的？

内核模块 ==> dev->work_q ==> node->{data,meta}_q
==> peer_node->work_q ==> peer_dev->{data,meta}_q ==> 内核模块

也就是说，device 中的队列都是和内核模块相关的，从内核模块中接收的包放在
dev->work_q 中，要发送到内核模块的数据放到 dev->{data,meta}_q 中。

从对端节点收到的包都放到这个节点的 node->work_q 队列中，要发送到这个节点的数据包
都放在 node->{data,meta}_q中。

# 一个 daemon 的进程，有多少个运行的线程？

## 只存在一段时间的线程

### connect_thread

在 daemon{} 结构中，一开始运行时，会创建一个 connect_thread 的线程，它的运行函数
是 connect_function()，但是一旦所有节点的连接建立之后，这个线程就会退出；在每次
定时器 connect_timer 定时器调用的时候，将会在节点断开的时候再次建立
connect_thread 这个线程。

## 在 daemon 整个生存时间都存在的线程

每个 node 结构有 3 个线程，每个 device 结构有 3 个线程。

# 一个 daemon 进程中，有多少个 libevent 事件在监听？

基本的有 5 个，加上每个节点 2 个，至少 7 个（1 个节点），至多 69 个（32 个节点）。

基本的：

    daemon->local_handler
    connect_timer->timer_handler
    kmod_check_timer->timer_handler
    dev->data_handler
    dev->meta_handler

节点的：

    node->data_handler
    node->meta_handler

由于每个事件都需要一个处理函数，因此我们来看看有多少个事件处理函数，就知道了至少
有多少个事件在监听了。

## daemon->local_handler

daemon{} 结构中，有一个 local_handler，它处理和内核模块的连接。

## timer->timer_handler

在 timer{} 中，有一个 timer_handler，这个函数处理定时器到时的事件。

## device->{data,meta}_handler

device 监听的是和内核模块连接的接口是否有数据可以读，也就是内核模块是否有数据包
发送到 server，需要 server 转发到对端节点。

## node->{data,meta}_handler

节点监听的事件是和节点连接的接口是否有数据可读，也就是对端节点是否有数据发送给本
机，data_handler 是处理数据链路的，meta_handler 是处理元数据链路的。

# 一个 daemon 进程中，有多少个定时器？

从顶层结构 daemon{} 开始分析，在 daemon.timer_base 结构中，包含了两个定时器：一
个是 connect_timer，一个是 kmod_check_timer。在每一个节点中，有一个 ping_timer
定时器。

connect_timer 的回调函数是 connect_timer_cb()，kmod_check_timer 的回调函数是
kmod_check_timer_cb()，ping_timer 的回调函数是 pint_timer_cb()。

>>> kmod_check_timer => kmod_check_timer()
>>> connect_timer => connect_timer_cb()
>>> ping_timer * nr_nodes => ping_timer_cb()

通过搜索 create_timer() 被调用的次数，通过删除定义、声明和文档的出现，发现只有以
下的结果：

daemon.c:290:	timer = create_timer(CONNECT_TIMER_TIMEOUT, connect_timer_cb, tb);
daemon.c:296:	timer = create_timer(KMOD_CHECK_TIMEOUT, kmod_check_timer_cb, tb);
node.c:355:		ping_timer = create_timer(node_list->ping, ping_timer_cb, node);

## connect_timer_cb()

简单地说，connect_timer_cb() 所做的事情包括：

1. 和所有节点建立连接
2. 告诉内核模块有哪些节点已经建立了连接。

在每次调用的时候，它会去检查是否和所有节点都建立了连接。如果没有建立连接，那么就
新建一个线程去完成和所有节点建立连接的任务。同时给内核模块发送一个
P_NODE_CONN_STATE 的 meta 包，对于每个节点，如果已经建立了 DATA 和 META 连接的话，
就认为和这个节点建立了连接，通过在数据包中的 node_to 字段的相应位设置了 1 来告诉
内核模块这个事实，同时设置 dev_id=MAX_DEVICES 表示告诉所有的设备。

## ping_timer_cb()

这个定时器是每个节点一个。每次被调用的时候，如果情况正常，就创建一个 P_{SC,NC}_PING
的 meta 包，挂入到节点的 meta_q 队列中。

如果 meta 没有连接，那么就没有什么事情可做的，因为这种包类型只能通过 meta 连接发
送，所以可以直接返回。如果尝试发送包的次数超过了限制，就认为连接已经断开，这时候
就删除节点的 dfd 和 mfd 的监听事件。能够这样做的原因是，发送一次 P_{SC,NC}_PING 的
包会使 node->ping_count 加 1，收到一个 P_{SC,NC}_PING_ACK 的包会使 node->ping_count
减 1。也就是说，如果限制次数是 3 的话，那么发送了 3 次 P_{SC,NC}_PING 的包，而没有
得到一次P_{SC,NC}_PING_ACK 的应答，那么就认为连接已经断开了。

## kmod_check_timer_cb()

在每次调用的时候，它会去检查内核模块是否已经卸载了。如果已经卸载，那么 server 进
程就退出。

# node->ping_timer_timeout node->max_ping_count node->ping_count 这些字段都是什么意思？

node->ping_timer_timeout 是节点的 ping 定时器的超时时间，每经过这样一个时间间隔，
节点的 ping 定时器就会运行，它将会调用 ping_timer_cb() 运行。

node->max_ping_count 是节点间最大的无响应心跳包个数。当系统中无响应的心跳包超过
了这个次数，就认为连接已经断开了。

node->ping_count 是节点间无响应心跳包的个数。在每次发送心跳包
（P_SC_PING,P_NC_PING）之后，这个计数器就会增加；在每次收到响应包
（P_SC_PING_ACK,P_NC_PING_ACK）之后，这个计数器就会减小。

在配置文件中，这些配置的字段分别是：

<pingtimeout>10</pingtimeout> ==> node->ping_timer_timeout
<maxpingcount>10</maxpingcount> ==> node->max_ping_count

在 Git 仓库的这个提交 68e67ba71f9eb2482322ef69969cd229d89164a5 之前，配置文件的
字段和代码中的字段分别是：

<ping>10</ping> ==> node_list->ping
<pingtimeout>10</pingtimeout> ==> node_list->pingtimeout

改动之后的字段的对应关系为：

node_list->ping ==> node->ping_timer_timeout
node_list->pingtimeout ==> node->max_ping_count
node->ping ==> node->ping_count

# 节点间是如何连接的？

节点间的连接由 node_list_do_connect() 完成。这个函数接收一个节点列表，尝试和除了
本地节点外的所有节点建立连接。总体上分为 3 个步骤：

1. 作为客户端，发起和其他节点的连接
2. 作为服务器，响应其他节点发起的连接
3. 作为客户端，接收服务器的响应

注意，当作为客户端时，一个节点只会对节点 id 小于自己的节点发起连接。在每次完成步
骤 1 之后，将会等待其他节点到来的连接，如果没有节点连接上来，在超过一个超时时间
之后，就会进行下一次尝试，尝试到了最大次数之后，就会终止当前的连接。节点间的连接
就会等到下一次连接定时器的到来。

节点间的连接代码如下，为了简化删除了一些代码：

```C
while (1) {
	FD_ZERO(&rfds);
	FD_SET(sfd, &rfds);

	client_connect_server_list(node_list, &rfds);
	nfds = select(SELECT_MAX_FDS, &rfds, NULL, NULL, &tv);
	if (nfds == 0) {
		n_try += 1;
		sec <<= 1;
		if (n_try > CONNECT_TRY)
			break;
	} else if (nfds > 0) {
		if (FD_ISSET(sfd, &rfds)) {
			ret = server_response_client(sfd, node_list);
			if (ret < 0)
				continue;
		} else {
			client_accept_server(node_list, &rfds);
		}
	}

	if ((ret = check_all_connected(node_list))) {
		log_info("all nodes connected!");
		break;
	}
}
```

在步骤 1 中，发起和 site 的连接时，要将正确的本地 site 的地址发送过去，这样可以
让对端知道是哪个节点发起的连接。需要这样做的原因是，一个节点可能会运行多个资源，
这样一个物理节点就会有多个 runsite 的实例，每个实例会有不同的 IP。

节点在收到其他节点的响应之后，它需要做的事情是安装节点的回调函数，这些回调函数要
处理的时间包括节点事件和定时器事件。

huruiqin
2015.4.17
