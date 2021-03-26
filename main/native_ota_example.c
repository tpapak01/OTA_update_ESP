/* OTA example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "esp_flash_partitions.h"
#include "esp_partition.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "protocol_examples_common.h"
#include "errno.h"

#if CONFIG_EXAMPLE_CONNECT_WIFI
#include "esp_wifi.h"
#endif

#define BUFFSIZE 1024
#define HASH_LEN 32 /* SHA-256 digest length */

static const char *TAG = "native_ota_example";
/*an ota data write buffer ready to write to the flash*/
static char ota_write_data[BUFFSIZE + 1] = { 0 };
extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");

#define OTA_URL_SIZE 256

static char FIRMWARE_URL[60];
static char IP_ADDRESS[30];
static char FILENAME[30];
static int exit_loop = 0;

static void http_cleanup(esp_http_client_handle_t client)
{
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
}

static void __attribute__((noreturn)) task_fatal_error(void)
{
    ESP_LOGE(TAG, "Exiting task due to fatal error...");
    (void)vTaskDelete(NULL);

    while (1) {
        ;
    }
}

static void print_sha256 (const uint8_t *image_hash, const char *label)
{
    char hash_print[HASH_LEN * 2 + 1];
    hash_print[HASH_LEN * 2] = 0;
    for (int i = 0; i < HASH_LEN; ++i) {
        sprintf(&hash_print[i * 2], "%02x", image_hash[i]);
    }
    ESP_LOGI(TAG, "%s: %s", label, hash_print);
}

static void infinite_loop(void)
{
    int i = 0;
    ESP_LOGI(TAG, "When a new firmware is available on the server, press the reset button to download it");
    while(1) {
        ESP_LOGI(TAG, "Waiting for a new firmware ... %d", ++i);
        vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
}

#include "freertos/event_groups.h"
static EventGroupHandle_t s_connect_event_group;
static esp_netif_t *s_example_esp_netif = NULL;
static const char *s_connection_name;
static esp_ip4_addr_t s_ip_addr; // Saves the ipv4 address of the esp32
#define GOT_IPV4_BIT BIT(0)
#define CONNECTED_BITS (GOT_IPV4_BIT)


static void on_got_ipv4(void *arg, esp_event_base_t event_base,
                      int32_t event_id, void *event_data)
{
    ESP_LOGI(TAG, "Got IPv4 event!: %d", event_id);
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    memcpy(&s_ip_addr, &event->ip_info.ip, sizeof(s_ip_addr));
    xEventGroupSetBits(s_connect_event_group, GOT_IPV4_BIT);
}

static void on_wifi_disconnect(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
	printf("BEGIN on_wifi_disconnect\n");
    ESP_LOGI(TAG, "Wi-Fi disconnected, trying to reconnect...");
    esp_err_t err = esp_wifi_connect();
    if (err == ESP_ERR_WIFI_NOT_STARTED) {
        return;
    }
    ESP_ERROR_CHECK(err);
}

void ota_example_task(void *pvParameters)
{

    esp_err_t err;
    /* update handle : set by esp_ota_begin(), must be freed via esp_ota_end() */
    esp_ota_handle_t update_handle = 0 ;
    const esp_partition_t *update_partition = NULL;

    printf("Starting OTA example\n");
    ESP_LOGI(TAG, "Starting OTA example");

    const esp_partition_t *configured = esp_ota_get_boot_partition();
    const esp_partition_t *running = esp_ota_get_running_partition();

    if (configured != running) {
        ESP_LOGW(TAG, "Configured OTA boot partition at offset 0x%08x, but running from offset 0x%08x",
                 configured->address, running->address);
        ESP_LOGW(TAG, "(This can happen if either the OTA boot data or preferred boot image become corrupted somehow.)");
    }
    ESP_LOGI(TAG, "Running partition type %d subtype %d (offset 0x%08x)",
             running->type, running->subtype, running->address);

    strcpy(FIRMWARE_URL,"https://");
    strcat(FIRMWARE_URL, IP_ADDRESS);
    strcat(FIRMWARE_URL, ":8070/");
    strcat(FIRMWARE_URL, FILENAME);
    strcpy(FIRMWARE_URL + strlen(FIRMWARE_URL)-1, ".bin");

    esp_http_client_config_t config = {
    	.url = FIRMWARE_URL,
        //.url = CONFIG_EXAMPLE_FIRMWARE_UPG_URL,
        .cert_pem = (char *)server_cert_pem_start,
        .timeout_ms = CONFIG_EXAMPLE_OTA_RECV_TIMEOUT,
    };

#ifdef CONFIG_EXAMPLE_FIRMWARE_UPGRADE_URL_FROM_STDIN
    char url_buf[OTA_URL_SIZE];
    if (strcmp(config.url, "FROM_STDIN") == 0) {
        example_configure_stdin_stdout();
        fgets(url_buf, OTA_URL_SIZE, stdin);
        int len = strlen(url_buf);
        url_buf[len - 1] = '\0';
        config.url = url_buf;
    } else {
        ESP_LOGE(TAG, "Configuration mismatch: wrong firmware upgrade image url");
        abort();
    }
#endif

#ifdef CONFIG_EXAMPLE_SKIP_COMMON_NAME_CHECK
    config.skip_cert_common_name_check = true;
#endif

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialise HTTP connection");
        task_fatal_error();
    }
    err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        task_fatal_error();
    }
    esp_http_client_fetch_headers(client);

    update_partition = esp_ota_get_next_update_partition(NULL);
    ESP_LOGI(TAG, "Writing to partition type %d subtype %d at offset 0x%x", update_partition->type,
             update_partition->subtype, update_partition->address);
    assert(update_partition != NULL);

    int binary_file_length = 0;
    /*deal with all receive packet*/
    bool image_header_was_checked = false;
    while (1) {
        int data_read = esp_http_client_read(client, ota_write_data, BUFFSIZE);
        if (data_read < 0) {
            ESP_LOGE(TAG, "Error: SSL data read error");
            http_cleanup(client);
            task_fatal_error();
        } else if (data_read > 0) {
            if (image_header_was_checked == false) {
                esp_app_desc_t new_app_info;
                if (data_read > sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t)) {
                    // check current version with downloading
                    memcpy(&new_app_info, &ota_write_data[sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t)], sizeof(esp_app_desc_t));
                    ESP_LOGI(TAG, "New firmware version: %s", new_app_info.version);

                    esp_app_desc_t running_app_info;
                    if (esp_ota_get_partition_description(running, &running_app_info) == ESP_OK) {
                        ESP_LOGI(TAG, "Running firmware version: %s", running_app_info.version);
                    }

                    const esp_partition_t* last_invalid_app = esp_ota_get_last_invalid_partition();
                    esp_app_desc_t invalid_app_info;
                    if (esp_ota_get_partition_description(last_invalid_app, &invalid_app_info) == ESP_OK) {
                        ESP_LOGI(TAG, "Last invalid firmware version: %s", invalid_app_info.version);
                    }

                    // check current version with last invalid partition
                    if (last_invalid_app != NULL) {
                        if (memcmp(invalid_app_info.version, new_app_info.version, sizeof(new_app_info.version)) == 0) {
                            ESP_LOGW(TAG, "New version is the same as invalid version.");
                            ESP_LOGW(TAG, "Previously, there was an attempt to launch the firmware with %s version, but it failed.", invalid_app_info.version);
                            ESP_LOGW(TAG, "The firmware has been rolled back to the previous version.");
                            http_cleanup(client);
                            infinite_loop();
                        }
                    }
/*
#ifndef CONFIG_EXAMPLE_SKIP_VERSION_CHECK
                    if (memcmp(new_app_info.version, running_app_info.version, sizeof(new_app_info.version)) == 0) {
                        ESP_LOGW(TAG, "Current running version is the same as a new. We will not continue the update.");
                        http_cleanup(client);
                        infinite_loop();
                    }
#endif
*/

                    image_header_was_checked = true;

                    err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &update_handle);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
                        http_cleanup(client);
                        task_fatal_error();
                    }
                    ESP_LOGI(TAG, "esp_ota_begin succeeded");
                } else {
                    ESP_LOGE(TAG, "received package is not fit len");
                    http_cleanup(client);
                    task_fatal_error();
                }
            }
            err = esp_ota_write( update_handle, (const void *)ota_write_data, data_read);
            if (err != ESP_OK) {
            	printf("Error at esp_ota_write, %x\n", err);
                http_cleanup(client);
                task_fatal_error();
            }
            binary_file_length += data_read;
            ESP_LOGD(TAG, "Written image length %d", binary_file_length);
        } else if (data_read == 0) {
           /*
            * As esp_http_client_read never returns negative error code, we rely on
            * `errno` to check for underlying transport connectivity closure if any
            */
            if (errno == ECONNRESET || errno == ENOTCONN) {
                ESP_LOGE(TAG, "Connection closed, errno = %d", errno);
                break;
            }
            if (esp_http_client_is_complete_data_received(client) == true) {
                ESP_LOGI(TAG, "Connection closed");
                break;
            }
        }
    }
    ESP_LOGI(TAG, "Total Write binary data length: %d", binary_file_length);
    if (esp_http_client_is_complete_data_received(client) != true) {
        ESP_LOGE(TAG, "Error in receiving complete file");
        http_cleanup(client);
        task_fatal_error();
    }

    err = esp_ota_end(update_handle);
    if (err != ESP_OK) {
        if (err == ESP_ERR_OTA_VALIDATE_FAILED) {
            ESP_LOGE(TAG, "Image validation failed, image is corrupted");
        }
        ESP_LOGE(TAG, "esp_ota_end failed (%s)!", esp_err_to_name(err));
        http_cleanup(client);
        task_fatal_error();
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
        http_cleanup(client);
        task_fatal_error();
    }
    ESP_LOGI(TAG, "Prepare to restart system!");
    esp_restart();
    return ;
}

static bool diagnostic(void)
{
    gpio_config_t io_conf;
    io_conf.intr_type    = GPIO_PIN_INTR_DISABLE;
    io_conf.mode         = GPIO_MODE_INPUT;
    io_conf.pin_bit_mask = (1ULL << CONFIG_EXAMPLE_GPIO_DIAGNOSTIC);
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    io_conf.pull_up_en   = GPIO_PULLUP_ENABLE;
    gpio_config(&io_conf);

    ESP_LOGI(TAG, "Diagnostics (5 sec)...");
    vTaskDelay(5000 / portTICK_PERIOD_MS);

    bool diagnostic_is_ok = gpio_get_level(CONFIG_EXAMPLE_GPIO_DIAGNOSTIC);

    gpio_reset_pin(CONFIG_EXAMPLE_GPIO_DIAGNOSTIC);
    return diagnostic_is_ok;
}















/*
   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_bt_api.h"
#include "esp_bt_device.h"
#include "esp_spp_api.h"
#include "esp_vfs.h"




#include "esp_gap_ble_api.h"
#include "esp_gattc_api.h"
#include "esp_system.h"
#include "esp_gatt_common_api.h"

#include "time.h"
#include "sys/time.h"


#include "driver/gpio.h"


#define SPP_TAG "BT_MODULE"
#define SPP_SERVER_NAME "SPP_SERVER"
#define DEVICE_NAME "DCO_PSI_A"
#define SPP_SHOW_DATA 1
#define SPP_SHOW_SPEED 0
#define SPP_SHOW_MODE SPP_SHOW_DATA    /*Choose show mode: show data or speed*/

#define SPP_TASK_SIG_WORK_DISPATCH          (0x01)

static const esp_spp_mode_t esp_spp_mode = ESP_SPP_MODE_VFS;

static struct timeval time_new, time_old;
//static long data_num = 0;

static const esp_spp_sec_t sec_mask = ESP_SPP_SEC_AUTHENTICATE;
static const esp_spp_role_t role_slave = ESP_SPP_ROLE_SLAVE;
static const esp_spp_role_t role_master = ESP_SPP_ROLE_MASTER;


/**
 * initiator defines
 */
static esp_bd_addr_t peer_bd_addr;
static uint8_t peer_bdname_len;
static char peer_bdname[ESP_BT_GAP_MAX_BDNAME_LEN + 1];
static const char remote_device_name[] = "RemoteDev";

char dev_name[40];
//static const esp_bt_inq_mode_t inq_mode = ESP_BT_INQ_MODE_GENERAL_INQUIRY;
//static const uint8_t inq_len = 30;
//static const uint8_t inq_num_rsps = 0;




#if (SPP_SHOW_MODE == SPP_SHOW_DATA)
#define SPP_DATA_LEN 128
#else
#define SPP_DATA_LEN ESP_SPP_MAX_MTU
#endif
static uint8_t spp_data[SPP_DATA_LEN];
#if (SPP_SHOW_MODE == SPP_SHOW_SPEED)
static void print_speed(void)
{
    float time_old_s = time_old.tv_sec + time_old.tv_usec / 1000000.0;
    float time_new_s = time_new.tv_sec + time_new.tv_usec / 1000000.0;
    float time_interval = time_new_s - time_old_s;
    float speed = data_num * 8 / time_interval / 1000.0;
    ESP_LOGI(SPP_TAG, "speed(%fs ~ %fs): %f kbit/s" , time_old_s, time_new_s, speed);
    data_num = 0;
    time_old.tv_sec = time_new.tv_sec;
    time_old.tv_usec = time_new.tv_usec;
}
#endif

/*
 * task defines
 */
static xQueueHandle spp_task_task_queue = NULL;
static xTaskHandle spp_task_task_handle = NULL;




/**
 * @brief     handler for the dispatched work
 */
typedef void (* spp_task_cb_t) (uint16_t event, void *param);

/* message to be sent */
typedef struct {
    uint16_t             sig;      /*!< signal to spp_task_task */
    uint16_t             event;    /*!< message event id */
    spp_task_cb_t        cb;       /*!< context switch callback */
    void                 *param;   /*!< parameter area needs to be last */
} spp_task_msg_t;

/**
 * @brief     handler for write and read
 */
typedef void (* spp_wr_task_cb_t) (void *fd);





/**
 * @brief     parameter deep-copy function to be customized
 */
typedef void (* spp_task_copy_cb_t) (spp_task_msg_t *msg, void *p_dest, void *p_src);


void esp_bt_gap_cb(esp_bt_gap_cb_event_t event, esp_bt_gap_cb_param_t *param);

//--------------------------------------------------------

int uart_to_bt(int bt_fd, TickType_t ticks_to_wait);

void spp_read_handle (void * param);

void spp_wr_task_start_up(spp_wr_task_cb_t p_cback, int fd);

void esp_spp_cb(esp_spp_cb_event_t event, esp_spp_cb_param_t *param);

//--------------------------------------------------------

static void spp_task_work_dispatched(spp_task_msg_t *msg);

static void spp_task_task_handler(void *arg);

void spp_task_task_start_up(void);

void spp_wr_task_shut_down(void);

void init_BT(void);


void define_output_desc(int bluetooth_fd);

int output_desc = STDOUT_FILENO;


void backtofactory()
{
    esp_partition_iterator_t  pi ;                                  // Iterator for find
    const esp_partition_t*    factory ;                             // Factory partition
    esp_err_t                 err ;

    dprintf(output_desc, "ready to find partition\n");
    pi = esp_partition_find ( ESP_PARTITION_TYPE_APP,               // Get partition iterator for
                              ESP_PARTITION_SUBTYPE_APP_FACTORY,    // factory partition
                              "factory" ) ;
    if ( pi == NULL )                                               // Check result
    {
        ESP_LOGE ( "MAIN APP", "Failed to find factory partition" ) ;
    }
    else
    {
        factory = esp_partition_get ( pi ) ;                        // Get partition struct
        esp_partition_iterator_release ( pi ) ;                     // Release the iterator
        err = esp_ota_set_boot_partition ( factory ) ;              // Set partition for boot
        if ( err != ESP_OK )                                        // Check error
	{
            ESP_LOGE ( "MAIN APP", "Failed to set boot partition" ) ;
	}
	else
	{
            esp_restart() ;                                         // Restart ESP
        }
    }
}

void define_output_desc(int bluetooth_fd){

		dprintf(output_desc,"Output changed to Bluetooth\n");
		output_desc = bluetooth_fd;
		printf("OUTPUT_DESC = %d\n", output_desc);


}


static bool get_name_from_eir(uint8_t *eir, char *bdname, uint8_t *bdname_len)
{
    uint8_t *rmt_bdname = NULL;
    uint8_t rmt_bdname_len = 0;

    if (!eir) {
        return false;
    }

    rmt_bdname = esp_bt_gap_resolve_eir_data(eir, ESP_BT_EIR_TYPE_CMPL_LOCAL_NAME, &rmt_bdname_len);
    if (!rmt_bdname) {
        rmt_bdname = esp_bt_gap_resolve_eir_data(eir, ESP_BT_EIR_TYPE_SHORT_LOCAL_NAME, &rmt_bdname_len);
    }

    if (rmt_bdname) {
        if (rmt_bdname_len > ESP_BT_GAP_MAX_BDNAME_LEN) {
            rmt_bdname_len = ESP_BT_GAP_MAX_BDNAME_LEN;
        }

        if (bdname) {
            memcpy(bdname, rmt_bdname, rmt_bdname_len);
            bdname[rmt_bdname_len] = '\0';
        }
        if (bdname_len) {
            *bdname_len = rmt_bdname_len;
        }
        return true;
    }

    return false;
}

int uart_to_bt(int bt_fd, TickType_t ticks_to_wait){


	memcpy(spp_data, (uint8_t*)"abcde", 5);
	int size = 5;
	//int size = uart_read_bytes(UART_PORT,spp_data,SPP_DATA_LEN,ticks_to_wait);
	if(size <= 0 ){
		return 0;
	}
	int recv_flag = 0;
//	ESP_LOGI(SPP_TAG,"UART -> %d bytes", size);
	uint8_t *ptr = spp_data;
	int remain= size;
	while( remain > 0 ){
		int res = write(bt_fd , ptr, remain);
		ESP_LOGI(SPP_TAG, "BT <- %d bytes", res);
		if( res < 0 ){
			return -1;
		}
		if (res == 0){
			vTaskDelay(1);
			continue;
		}
		remain -= res;
		ptr  += res;
	}
//	ESP_LOGI(SPP_TAG,"Entered character %s",spp_data);
	return size;
}

#define SPP_BULK_RD_THRESHOLD		512

void spp_read_handle (void * param){
    int fd = (int)param;

    ESP_LOGI(SPP_TAG, "BT connected");
    //uart_flush(UART_PORT);

    for (;;)
    {

        //size_t avail_now = 0;
        //uart_get_buffered_data_len(UART_PORT, &avail_now);
        //if (avail_now >= SPP_BULK_RD_THRESHOLD) {
            // Send available data from UART to BT first
    		/*
            int remain = 5;
            //while (remain >= SPP_DATA_LEN) {
                int tx_size = uart_to_bt(fd, 0);
                if (tx_size < 0)
                    goto disconnected;
                //if (!tx_size)
                //    break;
                remain -= tx_size;
             */
            //}
        //}

        // Try receive data from BT
        int size = read(fd, spp_data, SPP_DATA_LEN);
        if (size < 0) {
            goto disconnected;
        }
        if (size > 0) {
            //uart_write_bytes(UART_PORT, (const char *)spp_data, size);
        	printf("GOT %c\n", (char) spp_data[0]);
        	if (spp_data[0] == 'z'){
        		exit_loop = 1;
        	} else {
        		if (strstr((char*)spp_data, " ") != NULL) {
					const char deli[] = " ";
					strcpy(IP_ADDRESS, strtok((char*)spp_data, deli)); // can also call strtok(str, "["); and not use variable deli at all
					strcpy(FILENAME, strtok(NULL, deli));
					FILENAME[strlen(FILENAME)-1] = '\0';
					dprintf(output_desc, "%s %s\n", IP_ADDRESS, FILENAME);
        		}
        	}



            continue;
        }
        else printf("DAMN...\n");
        //if (avail_now < SPP_BULK_RD_THRESHOLD) {
            // Read UART waiting several ticks for the new data
        //    if (uart_to_bt(fd, avail_now ? 1 : 2) < 0)
        //        goto disconnected;
        //}
        vTaskDelay(5000/portTICK_PERIOD_MS);
    }

disconnected:
    ESP_LOGI(SPP_TAG, "BT disconnected");
    spp_wr_task_shut_down();
}


void esp_spp_cb(esp_spp_cb_event_t event, esp_spp_cb_param_t *param)
{
    switch (event) {
    case ESP_SPP_INIT_EVT:
        ESP_LOGI(SPP_TAG, "ESP_SPP_INIT_EVT");
        esp_bt_dev_set_device_name(DEVICE_NAME);
        esp_bt_gap_set_scan_mode(ESP_BT_CONNECTABLE, ESP_BT_GENERAL_DISCOVERABLE);
//        esp_bt_gap_start_discovery(inq_mode, inq_len, inq_num_rsps);
        esp_spp_start_srv(sec_mask,role_slave, 0, SPP_SERVER_NAME);
        break;
    case ESP_SPP_DISCOVERY_COMP_EVT:
        ESP_LOGI(SPP_TAG, "ESP_SPP_DISCOVERY_COMP_EVT: status=%d scn_num=%d", param->disc_comp.status, param->disc_comp.scn_num);
        if(param->disc_comp.status == ESP_SPP_SUCCESS){
        	esp_spp_connect(sec_mask, role_master, param->disc_comp.scn[0],peer_bd_addr);
        }
        break;
    case ESP_SPP_OPEN_EVT:
        ESP_LOGI(SPP_TAG, "ESP_SPP_OPEN_EVT");
        esp_spp_write(param->srv_open.handle,SPP_DATA_LEN,spp_data);
        gettimeofday(&time_old,NULL);
        break;
    case ESP_SPP_CLOSE_EVT:
        ESP_LOGI(SPP_TAG, "ESP_SPP_CLOSE_EVT");
        break;
    case ESP_SPP_START_EVT:
        ESP_LOGI(SPP_TAG, "ESP_SPP_START_EVT");
        break;
    case ESP_SPP_CL_INIT_EVT:
        ESP_LOGI(SPP_TAG, "ESP_SPP_CL_INIT_EVT");
        break;
    case ESP_SPP_DATA_IND_EVT:
#if (SPP_SHOW_MODE == SPP_SHOW_DATA)
        ESP_LOGI(SPP_TAG, "ESP_SPP_DATA_IND_EVT len=%d handle=%d",
                 param->data_ind.len, param->data_ind.handle);
        esp_log_buffer_hex("",param->data_ind.data,param->data_ind.len);
        esp_log_buffer_char("Received string data",param->data_ind.data,param->data_ind.len);

		printf("the message sent from the phone to the esp over Bluetooth is %s", (char*)param->data_ind.data);


        esp_spp_write(param->data_ind.handle,SPP_DATA_LEN,spp_data);
#else
        gettimeofday(&time_new, NULL);
        data_num += param->data_ind.len;
        if (time_new.tv_sec - time_old.tv_sec >= 3) {
            print_speed();
        }
#endif
        break;
    case ESP_SPP_CONG_EVT:
#if (SPP_SHOW_MODE == SPP_SHOW_DATA)
        ESP_LOGI(SPP_TAG, "ESP_SPP_CONG_EVT cong=%d", param->cong.cong);
#endif
        if (param->cong.cong == 0) {
            esp_spp_write(param->cong.handle, SPP_DATA_LEN, spp_data);
        }
        break;
    case ESP_SPP_WRITE_EVT:
#if (SPP_SHOW_MODE == SPP_SHOW_DATA)
        ESP_LOGI(SPP_TAG, "ESP_SPP_WRITE_EVT len=%d cong=%d", param->write.len , param->write.cong);
        esp_log_buffer_hex("",spp_data,SPP_DATA_LEN);

#else
        gettimeofday(&time_new, NULL);
        data_num += param->write.len;
        if (time_new.tv_sec - time_old.tv_sec >= 3) {
            print_speed();
        }
#endif
        if (param->write.cong == 0) {
            esp_spp_write(param->write.handle, SPP_DATA_LEN,spp_data);
        }
        break;
    case ESP_SPP_SRV_OPEN_EVT:
        ESP_LOGI(SPP_TAG, "ESP_SPP_SRV_OPEN_EVT");
        define_output_desc(param->srv_open.fd);
        spp_wr_task_start_up(spp_read_handle, param->srv_open.fd);
        gettimeofday(&time_old, NULL);
        break;
    default:
        break;
    }
}

void esp_bt_gap_cb(esp_bt_gap_cb_event_t event, esp_bt_gap_cb_param_t *param)
{
    switch (event) {
    case ESP_BT_GAP_AUTH_CMPL_EVT:{
        if (param->auth_cmpl.stat == ESP_BT_STATUS_SUCCESS) {
            ESP_LOGI(SPP_TAG, "authentication success: %s", param->auth_cmpl.device_name);
            esp_log_buffer_hex(SPP_TAG, param->auth_cmpl.bda, ESP_BD_ADDR_LEN);
        } else {
            ESP_LOGE(SPP_TAG, "authentication failed, status:%d", param->auth_cmpl.stat);
        }
        break;
    }
    case ESP_BT_GAP_PIN_REQ_EVT:{
        ESP_LOGI(SPP_TAG, "ESP_BT_GAP_PIN_REQ_EVT min_16_digit:%d", param->pin_req.min_16_digit);
        if (param->pin_req.min_16_digit) {
            ESP_LOGI(SPP_TAG, "Input pin code: 0000 0000 0000 0000");
            esp_bt_pin_code_t pin_code = {0};
            esp_bt_gap_pin_reply(param->pin_req.bda, true, 16, pin_code);
        } else {
            ESP_LOGI(SPP_TAG, "Input pin code: 1234");
            esp_bt_pin_code_t pin_code;
            pin_code[0] = '1';
            pin_code[1] = '2';
            pin_code[2] = '3';
            pin_code[3] = '4';
            esp_bt_gap_pin_reply(param->pin_req.bda, true, 4, pin_code);
        }
        break;
    }

#if (CONFIG_BT_SSP_ENABLED == true)
    case ESP_BT_GAP_CFM_REQ_EVT:
        ESP_LOGI(SPP_TAG, "ESP_BT_GAP_CFM_REQ_EVT Please compare the numeric value: %d", param->cfm_req.num_val);
        esp_bt_gap_ssp_confirm_reply(param->cfm_req.bda, true);
        break;
    case ESP_BT_GAP_KEY_NOTIF_EVT:
        ESP_LOGI(SPP_TAG, "ESP_BT_GAP_KEY_NOTIF_EVT passkey:%d", param->key_notif.passkey);
        break;
    case ESP_BT_GAP_KEY_REQ_EVT:
        ESP_LOGI(SPP_TAG, "ESP_BT_GAP_KEY_REQ_EVT Please enter passkey!");
        break;
#endif
    case ESP_BT_GAP_DISC_RES_EVT:
        ESP_LOGI(SPP_TAG, "ESP_BT_GAP_DISC_RES_EVT");
        esp_log_buffer_hex(SPP_TAG, param->disc_res.bda, ESP_BD_ADDR_LEN);
        for (int i = 0; i < param->disc_res.num_prop; i++){
            if (param->disc_res.prop[i].type == ESP_BT_GAP_DEV_PROP_EIR
                && get_name_from_eir(param->disc_res.prop[i].val, peer_bdname, &peer_bdname_len)){
                esp_log_buffer_char(SPP_TAG, peer_bdname, peer_bdname_len);
                if (strlen(remote_device_name) == peer_bdname_len
                    && strncmp(peer_bdname, remote_device_name, peer_bdname_len) == 0) {
                    memcpy(peer_bd_addr, param->disc_res.bda, ESP_BD_ADDR_LEN);
                    esp_spp_start_discovery(peer_bd_addr);
                    esp_bt_gap_cancel_discovery();
                }
            }
        }
        break;
    case ESP_BT_GAP_DISC_STATE_CHANGED_EVT:
    	ESP_LOGI(SPP_TAG,"ESP_BT_GAP_DISC_STATE_CHANGED_EVT");
    	break;
    case ESP_BT_GAP_RMT_SRVCS_EVT:
        ESP_LOGI(SPP_TAG, "ESP_BT_GAP_RMT_SRVCS_EVT");
        break;
    case ESP_BT_GAP_RMT_SRVC_REC_EVT:
        ESP_LOGI(SPP_TAG, "ESP_BT_GAP_RMT_SRVC_REC_EVT");
        break;

    default: {
        ESP_LOGI(SPP_TAG, "event: %d", event);
        break;
    }
    }
    return;
}



static void spp_task_work_dispatched(spp_task_msg_t *msg)
{
    if (msg->cb) {
        msg->cb(msg->event, msg->param);
    }
}

static void spp_task_task_handler(void *arg)
{
    spp_task_msg_t msg;
    for (;;) {
        if (pdTRUE == xQueueReceive(spp_task_task_queue, &msg, (portTickType)portMAX_DELAY)) {
            ESP_LOGD(SPP_TAG, "%s, sig 0x%x, 0x%x", __func__, msg.sig, msg.event);
            switch (msg.sig) {
            case SPP_TASK_SIG_WORK_DISPATCH:
                spp_task_work_dispatched(&msg);
                break;
            default:
                ESP_LOGW(SPP_TAG, "%s, unhandled sig: %d", __func__, msg.sig);
                break;
            }

            if (msg.param) {
                free(msg.param);
            }
        }
        vTaskDelay(1);
    }
}


void spp_task_task_start_up(void){
	spp_task_task_queue = xQueueCreate(10,sizeof(spp_task_msg_t));
	xTaskCreate(spp_task_task_handler,"BTAPP",2048,NULL,10,spp_task_task_handle);
}

void spp_task_task_shut_down(void)
{
    if (spp_task_task_handle) {
        vTaskDelete(spp_task_task_handle);
        spp_task_task_handle = NULL;
    }
    if (spp_task_task_queue) {
        vQueueDelete(spp_task_task_queue);
        spp_task_task_queue = NULL;
    }
}

void spp_wr_task_start_up(spp_wr_task_cb_t p_cback, int fd)
{
    xTaskCreate(p_cback, "write_read", 4096, (void *)fd, 5, NULL);
}
void spp_wr_task_shut_down(void)
{
    vTaskDelete(NULL);
}




void init_BT(void)
{
	printf("BEGIN init_BT\n");
	/*
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK( ret );
    */

    //spp_uart_init();
//    ESP_ERROR_CHECK(recv_dev_id(UART_PORT));

	esp_err_t ret;

    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_BLE));

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    if ((ret = esp_bt_controller_init(&bt_cfg)) != ESP_OK) {
        ESP_LOGE(SPP_TAG, "%s esp_bt_controller_init failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    else printf("esp_bt_controller_init SUCCESS\n");

    if ((ret = esp_bt_controller_enable(ESP_BT_MODE_BTDM)) != ESP_OK) {
        ESP_LOGE(SPP_TAG, "%s esp_bt_controller_enable failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    else printf("esp_bt_controller_enable SUCCESS\n");

    if ((ret = esp_bluedroid_init()) != ESP_OK) {
        ESP_LOGE(SPP_TAG, "%s esp_bluedroid_init failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    else printf("esp_bluedroid_init SUCCESS\n");


    if ((ret = esp_bluedroid_enable()) != ESP_OK) {
        ESP_LOGE(SPP_TAG, "%s esp_bluedroid_enable failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    else printf("esp_bluedroid_enable SUCCESS\n");

    if ((ret = esp_bt_gap_register_callback(esp_bt_gap_cb)) != ESP_OK) {
        ESP_LOGE(SPP_TAG, "%s esp_bt_gap_register_callback failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    else printf("esp_bt_gap_register_callback SUCCESS\n");

    if ((ret = esp_spp_register_callback(esp_spp_cb)) != ESP_OK) {
        ESP_LOGE(SPP_TAG, "%s esp_spp_register_callback failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    else printf("esp_spp_register_callback SUCCESS\n");

    if ((ret = esp_spp_vfs_register()) != ESP_OK) {
		ESP_LOGE(SPP_TAG, "%s esp_spp_vfs_register failed: %s\n", __func__, esp_err_to_name(ret));
		return;
    } else printf("esp_spp_vfs_register SUCCESS\n");

    spp_task_task_start_up();


    if ((ret = esp_spp_init(esp_spp_mode)) != ESP_OK) {
        ESP_LOGE(SPP_TAG, "%s esp_spp_init failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    else printf("esp_spp_init SUCCESS\n");


#if (CONFIG_BT_SSP_ENABLED == true)
    /* Set default parameters for Secure Simple Pairing */
    esp_bt_sp_param_t param_type = ESP_BT_SP_IOCAP_MODE;
    esp_bt_io_cap_t iocap = ESP_BT_IO_CAP_IO;
    if ((ret = esp_bt_gap_set_security_param(param_type, &iocap, sizeof(uint8_t))) != ESP_OK) {
    	ESP_LOGE(SPP_TAG, "%s esp_bt_gap_set_security_param failed: %s\n", __func__, esp_err_to_name(ret));
    	return;
    }
    else printf("esp_bt_gap_set_security_param SUCCESS\n");

#endif

    /*
     * Set default parameters for Legacy Pairing
     * Use variable pin, input pin code when pairing
     */
    esp_bt_pin_type_t pin_type = ESP_BT_PIN_TYPE_VARIABLE;
    esp_bt_pin_code_t pin_code;
    if ((ret = esp_bt_gap_set_pin(pin_type, 0, pin_code)) != ESP_OK) {
    	ESP_LOGE(SPP_TAG, "%s esp_bt_gap_set_pin failed: %s\n", __func__, esp_err_to_name(ret));
    	return;
    }
    else printf("esp_bt_gap_set_pin SUCCESS\n");


}




























void app_main(void)
{

	strcpy(IP_ADDRESS,"192.168.192.127");
	strcpy(FILENAME,"udp_client ");


    uint8_t sha_256[HASH_LEN] = { 0 };
    esp_partition_t partition;

    // get sha256 digest for the partition table
    partition.address   = ESP_PARTITION_TABLE_OFFSET;
    partition.size      = ESP_PARTITION_TABLE_MAX_LEN;
    partition.type      = ESP_PARTITION_TYPE_DATA;
    esp_partition_get_sha256(&partition, sha_256);
    print_sha256(sha_256, "SHA-256 for the partition table: ");

    // get sha256 digest for bootloader
    partition.address   = ESP_BOOTLOADER_OFFSET;
    partition.size      = ESP_PARTITION_TABLE_OFFSET;
    partition.type      = ESP_PARTITION_TYPE_APP;
    esp_partition_get_sha256(&partition, sha_256);
    print_sha256(sha_256, "SHA-256 for bootloader: ");

    // get sha256 digest for running partition
    esp_partition_get_sha256(esp_ota_get_running_partition(), sha_256);
    print_sha256(sha_256, "SHA-256 for current firmware: ");

    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state;
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            // run diagnostic function ...
            bool diagnostic_is_ok = diagnostic();
            if (diagnostic_is_ok) {
                ESP_LOGI(TAG, "Diagnostics completed successfully! Continuing execution ...");
                esp_ota_mark_app_valid_cancel_rollback();
            } else {
                ESP_LOGE(TAG, "Diagnostics failed! Start rollback to the previous version ...");
                esp_ota_mark_app_invalid_rollback_and_reboot();
            }
        }
    }

    // Initialize NVS.
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // OTA app partition table has a smaller NVS partition size than the non-OTA
        // partition table. This size mismatch may cause NVS initialization to fail.
        // If this happens, we erase NVS partition and initialize NVS again.
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK( err );



    init_BT();



    ESP_ERROR_CHECK(esp_netif_init());
    	ESP_ERROR_CHECK(esp_event_loop_create_default());

    	/* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
    	 * Read "Establishing Wi-Fi or Ethernet Connection" section in
    	 * examples/protocols/README.md for more information about this function.
    	 */


    	//ESP_ERROR_CHECK(example_connect());

    	// init of the WIFI
    		ESP_LOGI(TAG,"Initialising WiFi");
    		wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    	    ESP_ERROR_CHECK( esp_wifi_init(&wifi_cfg) );

    	    if (s_connect_event_group != NULL) {
    	            printf("Invalid WIFI state\n");
    	    }
    	    s_connect_event_group = xEventGroupCreate();


    	    //UNCOMMENT FOR DYNAMIC IP, BUT COMMENT THE STATIC IP SECTION
    	    esp_netif_config_t netif_config = ESP_NETIF_DEFAULT_WIFI_STA(); // main configurations for a wifi station
    		esp_netif_t *netif = esp_netif_new(&netif_config);
    		assert(netif);
    		// adds the wifi station net interface
    		esp_netif_attach_wifi_station(netif);
    		// adding the default functions handlers for a wifi station to the event loop
    		esp_wifi_set_default_wifi_sta_handlers();


    		s_example_esp_netif = netif;

    		// adds the event handlers for both wifi connection and disconnection
    		ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &on_wifi_disconnect, NULL));
    		ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &on_got_ipv4, NULL));

    	#ifdef CONFIG_DCO_IPV6
    		// adds the event handlers for requesting a linklocal and getting the ipv6 address
    		ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, &on_wifi_connect, netif));
    		ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_GOT_IP6, &on_got_ipv6, NULL));
    	#endif /*CONFIG_DCO_IPV6*/

    		ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    		wifi_config_t wifi_config = {
    			.sta = {
    				.ssid = "DC Opportunities Lab 2.4",
    				.password = "DCO123DCO",
    			},
    		};
    		ESP_LOGI(TAG, "Connecting to %s...", wifi_config.sta.ssid);
    		ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    		ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));

    		ESP_ERROR_CHECK(esp_wifi_start());
    		ESP_ERROR_CHECK(esp_wifi_connect());
    		s_connection_name = "DC Opportunities Lab 2.4";

    		ESP_LOGI(TAG, "Waiting for IP");
    		xEventGroupWaitBits(s_connect_event_group, CONNECTED_BITS, true, true, portMAX_DELAY);

    		ESP_LOGI(TAG, "Connected to %s", s_connection_name);
    		ESP_LOGI(TAG, "IPv4 address: " IPSTR, IP2STR(&s_ip_addr));

    		while (exit_loop == 0){
    			vTaskDelay(500 / portTICK_PERIOD_MS);
    		}

    		esp_err_t ret;
    		esp_bluedroid_disable();
    		esp_bt_controller_disable();
    		if ((ret = esp_bt_controller_deinit()) != ESP_OK) {
				ESP_LOGE(SPP_TAG, "%s esp_bt_controller_deinit failed: %s\n", __func__, esp_err_to_name(ret));
				return;
    		}
    		else printf("esp_bt_controller_deinit SUCCESS\n");


    #if CONFIG_EXAMPLE_CONNECT_WIFI
    	 // Ensure to disable any WiFi power save mode, this allows best throughput
    	 // and hence timings for overall OTA operation.
    	esp_wifi_set_ps(WIFI_PS_NONE);
    #endif // CONFIG_EXAMPLE_CONNECT_WIFI



    xTaskCreate(&ota_example_task, "ota_example_task", 8192, NULL, 5, NULL);

}
