/**
 * @file traffic_repeater.cpp
 * @author Pavel Siska (siska@cesnet.cz)
 * @brief Module for simple traffic forwarding from server to client.
 * @version 1.0
 * @date 4.3.2021
 *   
 * @copyright Copyright (c) 2021 CESNET
 */

#include <iostream>
#include <thread>
#include <mutex>          
#include <ctime>
#include <csignal>
#include <cstring>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <libtrap/trap.h>
#include <unistd.h>
#include <getopt.h>

#define likely(x)   __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

// interface 0
#define IFC_NUM0 0

// Definition of basic module information - module name, module description, number of input and output interfaces.
#define MODULE_BASIC_INFO(BASIC) \
    BASIC("traffic_repeater", \
          "This module receive data from input interface and resend it " \
          "to the output interface based on given arguments in -i option.", \
          1, 1)

/**
 * @brief Definition of module parameters. 
 * 
 * Every parameter has short_opt, long_opt, description, flag whether an argument 
 * is required or it is optional and argument type which is NULL in case the 
 * parameter does not need argument.
 */
#define MODULE_PARAMS(PARAM) \
    PARAM('n', "no-eof", "Do not send terminate message via output IFC.", no_argument, "none") \
    PARAM('t', "flush-timeout", "Force data flush every t seconds to output IFC.", required_argument, "number")

trap_module_info_t *module_info = NULL;

// mutex for critical section
std::mutex mtx;           

// Global variable used by signal handler to end the traffic repeater.
static volatile int stop = 0;

// Global verbose level
int verbose;

volatile bool is_fmt_initialized = false;

/**
 * Function to handle SIGTERM and SIGINT signals used to stop the module.
 * @param [in] signal caught signal value.
 */
static void
termination_handler(const int signum) 
{
    if (signum == SIGINT || signum == SIGTERM) {
        if (verbose > 0)
     	   std::cerr << "Signal " << signum << " caught, exiting module." << std::endl;
        stop = 1;
    }
}

/**
 * Install signal handlee to SIGTERM and SIGINT signals.
 * @param [in] signal caught signal value.
 */
static int
install_signal_handler(struct sigaction &sigbreak)
{
    static const int signum[] = {SIGINT, SIGTERM};

    sigbreak.sa_handler = termination_handler;
    sigemptyset(&sigbreak.sa_mask);
    sigbreak.sa_flags = 0;

    for (int i = 0; signum[i] != SIGTERM; i++) {
        if (sigaction(signum[i], &sigbreak, NULL) != 0) {
            std::cerr << "sigaction() error." << std::endl;
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Function to resend received data from input interface to output interface.
 */
static void 
traffic_repeater(const bool send_eof)
{
    const void *data;
    uint16_t data_size;
    int ret;

    uint64_t received  = 0;
    uint64_t sent      = 0;

    time_t start;
    time_t end;

    // Set NULL to required format on input interface.
    trap_set_required_fmt(IFC_NUM0, TRAP_FMT_UNIREC, "");

    // Set timeout on trap_recv
    trap_ifcctl(TRAPIFC_INPUT, IFC_NUM0, TRAPCTL_SETTIMEOUT, 500000);

    time(&start);

    // main loop
    while (unlikely(stop == 0)) {
        ret = trap_recv(IFC_NUM0, &data, &data_size);
        if (ret == TRAP_E_OK) {
            // update counter
            received++;
            if (unlikely(data_size <= 1)) {
                if (verbose > 0)
                    std::cerr << "Info: Final record received, terminating repeater..." << std::endl;
                stop = 1;
            }
        } else if (ret == TRAP_E_FORMAT_CHANGED) {
            const char *spec = NULL;
            uint8_t data_fmt = TRAP_FMT_UNKNOWN;

            // update counter
            received++;

            // flush old data
            if (is_fmt_initialized) {
                trap_send_flush(IFC_NUM0);
            }

            // critical section
            mtx.lock();
            
            // Get the data format of senders output interface 
            // (the data format of the output interface it is connected to)
            if (trap_get_data_fmt(TRAPIFC_INPUT, IFC_NUM0, &data_fmt, &spec) != TRAP_E_OK) {
                is_fmt_initialized = false;
                std::cerr << "Data format was not loaded" << std::endl;
                mtx.unlock();
                break;
            }

            is_fmt_initialized = true;
            mtx.unlock();

            // Set the same data format to repeaters output interface
            trap_set_data_fmt(IFC_NUM0, TRAP_FMT_UNIREC, spec);
        } else {
            TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break)
        }

        if (unlikely(stop == 1 && send_eof == false)) {
            // do not send terminate message
            break;
        } else {
            ret = trap_send(IFC_NUM0, data, data_size);
            if (ret == TRAP_E_OK) {
                sent++;
            } else {
                TRAP_DEFAULT_SEND_DATA_ERROR_HANDLING(ret, continue, break)
            }
        }
    }

    // final flush
    if (is_fmt_initialized)
        trap_send_flush(IFC_NUM0);

    time(&end);

    std::cerr << "Info: Flows received: " << received  << std::endl;
    std::cerr << "Info: Flows sent: "     << sent      << std::endl;
    std::cerr << "Info: Time elapsed: "   << difftime(end, start) << " seconds" << std::endl;
}

/**
 * @brief Flush data on output interface every @p flush_timer seconds.
 */
static void 
data_flusher(const uint32_t flush_timer)
{
    time_t timer;
    time(&timer);

    timer += flush_timer;

    while (unlikely(stop == 0)) {
        usleep(100000);
        // critical section
        mtx.lock();
        if (time(NULL) > timer && is_fmt_initialized) {
            trap_send_flush(IFC_NUM0);
            timer += flush_timer;
        }
        mtx.unlock();
    }
}

int 
main(int argc, char **argv)
{
    char opt;
    bool send_eof = true;
    uint32_t flush_timer = 10;
    struct sigaction sigbreak;
    std::thread t1;

    // Macro allocates and initializes module_info structure according to MODULE_BASIC_INFO.
    INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
    
    // Let TRAP library parse program arguments, extract its parameters and initialize module interfaces.
    TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

    // Install SIGINT and SIGTERN signal handler. 
    install_signal_handler(sigbreak);

    // Parse program parameters and get configuration
    while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
        switch (opt) {
        case 'n':
            send_eof = false;
            break;
        case 't':
            flush_timer = std::stoul(optarg);
            break;
        default:
            std::cerr << "Error: Invalid arguments." << std::endl;
            goto failure;
        }
    }

    // Set verbosity level
    verbose = trap_get_verbose_level();
    if (verbose >= 0)
        std::cout << "Verbosity level: " << trap_get_verbose_level() << std::endl;
    
    // spawn flush thread 
    t1 = std::thread(data_flusher, flush_timer); 

    traffic_repeater(send_eof);
    stop = 1;

    // Wait for thread to finish 
    t1.join(); 

    TRAP_DEFAULT_FINALIZATION();
    FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
    return EXIT_SUCCESS;

failure:
    TRAP_DEFAULT_FINALIZATION();
    FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
    return EXIT_FAILURE;
}