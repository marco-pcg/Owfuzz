/**************************************************************************
 * Copyright (C) 2020-2021 by Hongjian Cao <haimohk@gmail.com>
 * *
 * This file is part of owfuzz.
 * *
 * Owfuzz is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * *
 * Owfuzz is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * *
 * You should have received a copy of the GNU General Public License
 * along with owfuzz.  If not, see <https://www.gnu.org/licenses/>.
 ****************************************************************************/
#include "config.h"
#include "../frames/legacy_registry.h"
#include "log.h"
#include "../../linux_wifi/control/kismet_wifi_control.h"

/*
	Open a provided 'cfg_file', if none is provided, use 'owfuzz.cfg'
*/
FILE *owfuzz_config_open(char *cfg_file)
{
    char path[512];
    char *slash;
    ssize_t length;
    if (cfg_file) return fopen(cfg_file, "r");
    length = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (length <= 0 || (size_t)length >= sizeof(path) - 1) return NULL;
    path[length] = '\0';
    slash = strrchr(path, '/');
    if (!slash || (size_t)(slash + 1 - path) + sizeof("owfuzz.cfg") > sizeof(path)) return NULL;
    strcpy(slash + 1, "owfuzz.cfg");
    fuzz_logger_log(FUZZ_LOG_DEBUG, "owfuzz.cfg: %s", path);
    return fopen(path, "r");
}

/*
	Pull from the owfuzz.cfg file the [sta-frames] settings
*/
static int owfuzz_config_get_frames(char *cfg_file, const char *section,
                                    uint8_t *frames, uint32_t *count)
{
    FILE *fp = owfuzz_config_open(cfg_file);
    char buf[256], name[64], heading[64];
    uint32_t n = 0;
    int enabled, in_section = 0;
    if (!fp || !frames || !count) { if (fp) fclose(fp); return -1; }
    *count = 0;
    while (fgets(buf, sizeof(buf), fp)) {
        if (buf[0] == '[') {
            in_section = sscanf(buf, "[%63[^]]]", heading) == 1 && !strcmp(heading, section);
            continue;
        }
        if (!in_section || buf[0] == '#' || buf[0] == '\n') continue;
        if (sscanf(buf, "%63[^=]=%d", name, &enabled) != 2 || enabled != 1) continue;
        const struct ow_wifi_frame *frame = ow_wifi_find_name(name);
        if (!frame || n >= 64) {
            fuzz_logger_log(FUZZ_LOG_ERR, "Unknown/unsupported frame or frame limit: %s", name);
            fclose(fp);
            return -1;
        }
        frames[n++] = frame->id;
    }
    if (ferror(fp)) { fclose(fp); return -1; }
    fclose(fp);
    *count = n;
    return 0;
}
int owfuzz_config_get_sta_frames(char *cfg_file, uint8_t *frames, uint32_t *count)
{ return owfuzz_config_get_frames(cfg_file, "sta-frames", frames, count); }
int owfuzz_config_get_ap_frames(char *cfg_file, uint8_t *frames, uint32_t *count)
{ return owfuzz_config_get_frames(cfg_file, "ap-frames", frames, count); }

/*
	Pull the [interfaces] information from the owfuzz.cfg file
*/
int owfuzz_config_get_interfaces(char *cfg_file, fuzzing_option *fo)
{
	FILE *fp1;
	char buf[256] = {0};
	int rc = 0;
	int cnt = 0;

	fp1 = owfuzz_config_open(NULL);
	if (fp1 == NULL)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "Failed to open '%s'.", NULL == cfg_file ? "owfuzz.cfg" : cfg_file);
		return -1;
	}

	while (!feof(fp1))
	{
		memset(buf, 0, sizeof(buf));
		if (fgets(buf, sizeof(buf), fp1))
		{
			if (buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n')
				continue;

			if (buf[0] == '[')
			{
				if (strstr(buf, "[interfaces]") && (rc == 0))
				{
					rc = 1;
					continue;
				}
				else
				{
					if (rc == 1)
					{
						rc = 0;
						break;
					}
					else
						continue;
				}
			}

			if (rc)
			{
				memset(fo->ois[cnt].osdep_iface_out, 0, sizeof(fo->ois[cnt].osdep_iface_out));
				sscanf(buf, "%[^=]=%hhd", fo->ois[cnt].osdep_iface_out, &fo->ois[cnt].channel);
				if (cnt == 0)
					fo->channel = fo->ois[cnt].channel;
				cnt++;
			}
		}
	}

	fo->ois_cnt = cnt;

	fclose(fp1);
	return 0;
}

/*
	Retrieve from the cfg_file the 'interfaces' section
*/
int owfuzz_config_get_channels(char *cfg_file, fuzzing_option *fo)
{
	FILE *fp1 = NULL;
	char buf[256] = {0};
	char iface[64] = {0};
	int rc = 0;
	int cnt = 0;

	fp1 = owfuzz_config_open(cfg_file);
	if (fp1 == NULL)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "Failed to open '%s'.", NULL == cfg_file ? "owfuzz.cfg" : cfg_file);
		return -1;
	}

	while (!feof(fp1))
	{
		memset(buf, 0, sizeof(buf));
		if (fgets(buf, sizeof(buf), fp1))
		{
			if (buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n')
				continue;

			if (buf[0] == '[')
			{
				if (strstr(buf, "[interfaces]") && (rc == 0))
				{
					rc = 1;
					continue;
				}
				else
				{
					if (rc == 1)
					{
						rc = 0;
						break;
					}
					else
						continue;
				}
			}

			if (rc)
			{
				memset(iface, 0, sizeof(iface));
				sscanf(buf, "%[^=]=%hhd", iface, &fo->ois[cnt].channel);
				fuzz_logger_log(FUZZ_LOG_DEBUG, "interface: %s, channel: %d", iface, fo->ois[cnt].channel);
				cnt++;
			}
		}
	}

	fo->ois_cnt = cnt;

	fclose(fp1);
	return 0;
}

int owfuzz_config_get_macs(char *cfg_file, fuzzing_option *fo)
{
	FILE *fp1 = NULL;
	char buf[512] = {0};
	char option_name[256] = {0};
	char option_value[256] = {0};
	int rc = 0;

	fp1 = owfuzz_config_open(cfg_file);
	if (fp1 == NULL)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "Failed to open '%s'.", NULL == cfg_file ? "owfuzz.cfg" : cfg_file);
		return -1;
	}

	while (!feof(fp1))
	{
		memset(buf, 0, sizeof(buf));
		if (fgets(buf, sizeof(buf), fp1))
		{
			if (buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n')
				continue;

			if (buf[0] == '[')
			{
				if (strstr(buf, "[fuzzing_option]") && (rc == 0))
				{
					rc = 1;
					continue;
				}
				else
				{
					if (rc == 1)
					{
						rc = 0;
						break;
					}
					else
						continue;
				}
			}

			if (rc)
			{
				memset(option_name, 0, sizeof(option_name));
				memset(option_value, 0, sizeof(option_value));

				sscanf(buf, "%[^=]=%s", option_name, option_value);

				fuzz_logger_log(FUZZ_LOG_DEBUG, "option_name: %s, option_value: %s", option_name, option_value);

				if (0 == strcmp(option_name, "target_mac"))
				{
					fo->target_addr = parse_mac(option_value);
				}

				if (0 == strcmp(option_name, "bssid"))
				{
					fo->bssid = parse_mac(option_value);
				}

				if (0 == strcmp(option_name, "source_mac"))
				{
					fo->source_addr = parse_mac(option_value);
				}
			}
		}
	}

	fclose(fp1);
	return 0;
}

int owfuzz_config_get_fuzzing_option(char *cfg_file, fuzzing_option *fo)
{
	FILE *fp1;
	char buf[512] = {0};
	char option_name[256] = {0};
	char option_value[256] = {0};
	int rc = 0;

	fp1 = owfuzz_config_open(cfg_file);
	if (fp1 == NULL)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "Failed to open '%s'.", NULL == cfg_file ? "owfuzz.cfg" : cfg_file);
		return -1;
	}

	while (!feof(fp1))
	{
		memset(buf, 0, sizeof(buf));
		if (fgets(buf, sizeof(buf), fp1))
		{
			if (buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n')
				continue;

			if (buf[0] == '[')
			{
				if (strstr(buf, "[fuzzing_option]") && (rc == 0))
				{
					rc = 1;
					continue;
				}
				else
				{
					if (rc == 1)
					{
						rc = 0;
						break;
					}
					else
						continue;
				}
			}

			if (rc)
			{
				memset(option_name, 0, sizeof(option_name));
				memset(option_value, 0, sizeof(option_value));

				// We want to cpature everything including spaces (i.e. a ssid might have a space), so we use [^\n] instead of %s
				sscanf(buf, "%[^=]=%[^\n]", option_name, option_value);

				fuzz_logger_log(FUZZ_LOG_DEBUG, "option_name: %s, option_value: %s", option_name, option_value);

				if (!strcmp(option_name, "fuzz_mode"))
				{
					strncpy(fo->mode, option_value, sizeof(fo->mode));
					if (strcmp(fo->mode, STA_MODE) == 0)
					{
						fo->fuzz_work_mode = FUZZ_WORK_MODE_STA;
					}
					else if (strcmp(fo->mode, AP_MODE) == 0)
					{
						fo->fuzz_work_mode = FUZZ_WORK_MODE_AP;
					}
					else if (strcmp(fo->mode, MITM_MODE) == 0)
					{
						fo->fuzz_work_mode = FUZZ_WORK_MODE_MITM;
					}
					else if (strcmp(fo->mode, P2P_MODE) == 0)
					{
						fo->fuzz_work_mode = FUZZ_WORK_MODE_P2P;
					}
					else if (strcmp(fo->mode, AWDL_MODE) == 0)
					{
						fo->fuzz_work_mode = FUZZ_WORK_MODE_AWDL;
					}
					else if (strcmp(fo->mode, MESH_MODE) == 0)
					{
						fo->fuzz_work_mode = FUZZ_WORK_MODE_MESH;
					}
				}
				else if (!strcmp(option_name, "target_mac"))
				{
					strncpy(fo->sztarget_addr, option_value, sizeof(fo->sztarget_addr) - 1);
					fo->target_addr = parse_mac(option_value);
				}
				else if (!strcmp(option_name, "bssid"))
				{
					strncpy(fo->szbssid, option_value, sizeof(fo->szbssid) - 1);
					fo->bssid = parse_mac(option_value);
				}
				else if (!strcmp(option_name, "source_mac"))
				{
					strncpy(fo->szsource_addr, option_value, sizeof(fo->szsource_addr) - 1);
					fo->source_addr = parse_mac(option_value);
				}
				else if (!strcmp(option_name, "target_ip"))
				{
					if (strlen(option_value))
					{
						strncpy(fo->target_ip, option_value, sizeof(fo->target_ip) - 1);
						if (inet_addr(fo->target_ip) == INADDR_NONE)
						{
							fuzz_logger_log(FUZZ_LOG_ERR, "Target's IP is error: %s", fo->target_ip);
							fclose(fp1);
							return -1;
						}
					}
				}
				else if (0 == strcmp(option_name, "ssid"))
				{
					if (strlen(option_value) > 32)
					{
						fuzz_logger_log(FUZZ_LOG_ERR, "ERROR: AP's SSID is too long, limit 32 bytes.");
						fclose(fp1);
						return -1;
					}

					if (strlen(option_value) != 0)
					{
						strncpy(fo->target_ssid, option_value, sizeof(fo->target_ssid) - 1);
					}
				}
				else if (!strcmp(option_name, "auth_type"))
				{
					if (strcmp(option_value, "OPEN_NONE") == 0)
					{
						fo->auth_type = OPEN_NONE;
					}
					else if (strcmp(option_value, "OPEN_WEP") == 0)
					{
						fo->auth_type = OPEN_WEP;
					}
					else if (strcmp(option_value, "SHARE_WEP") == 0)
					{
						fo->auth_type = SHARE_WEP;
					}
					else if (strcmp(option_value, "WPA_PSK_TKIP") == 0)
					{
						fo->auth_type = WPA_PSK_TKIP;
					}
					else if (strcmp(option_value, "WPA_PSK_AES") == 0)
					{
						fo->auth_type = WPA_PSK_AES;
					}
					else if (strcmp(option_value, "WPA_PSK_TKIP_AES") == 0)
					{
						fo->auth_type = WPA_PSK_TKIP_AES;
					}
					else if (strcmp(option_value, "WPA2_PSK_TKIP") == 0)
					{
						fo->auth_type = WPA2_PSK_TKIP;
					}
					else if (strcmp(option_value, "WPA2_PSK_AES") == 0)
					{
						fo->auth_type = WPA2_PSK_AES;
					}
					else if (strcmp(option_value, "WPA2_PSK_TKIP_AES") == 0)
					{
						fo->auth_type = WPA2_PSK_TKIP_AES;
					}
					else if (strcmp(option_value, "EAP_8021X") == 0)
					{
						fo->auth_type = EAP_8021X;
					}
					else if (strcmp(option_value, "WPA3") == 0)
					{
						fo->auth_type = WPA3;
					}
					else
					{
						fuzz_logger_log(FUZZ_LOG_ERR, "Fuzzing target's auth type is wrong.");
						fo->auth_type = WPA2_PSK_TKIP_AES;
					}
				}
				else if (!strcmp(option_name, "test_type"))
				{
					fo->test_type = atoi(option_value);
				}
				else if (!strcmp(option_name, "log_level"))
				{
					fo->log_level = atoi(option_value);
				}
				else if (!strcmp(option_name, "log_file"))
				{
					strncpy(fo->log_file, option_value, sizeof(fo->log_file) - 1);
				}
				else if (!strcmp(option_name, "seed"))
				{
					sscanf(option_value, "%lu", &fo->seed);
				}
			}
		}
	}

	fclose(fp1);
	return 0;
}

int owfuzz_config_get_ies_status(char *cfg_file, fuzzing_option *fo)
{
	FILE *fp1;
	char buf[256] = {0};
	char ie_type[64] = {0};
	int rc = 0, onoff;
	int ie_idx = 0;

	fp1 = owfuzz_config_open(cfg_file);
	if (fp1 == NULL)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "Failed to open '%s'.", NULL == cfg_file ? "owfuzz.cfg" : cfg_file);
		return -1;
	}

	while (!feof(fp1))
	{
		memset(buf, 0, sizeof(buf));
		if (fgets(buf, sizeof(buf), fp1))
		{
			if (buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n')
				continue;

			if (buf[0] == '[')
			{
				if (strstr(buf, "[ies-status]") && (rc == 0))
				{
					rc = 1;
					continue;
				}
				else
				{
					if (rc == 1)
					{
						rc = 0;
						break;
					}
					else
						continue;
				}
			}

			if (rc)
			{
				onoff = 0;
				sscanf(buf, "%[^=]=%d", ie_type, &onoff);
				if (onoff == 1)
				{
					// printf("%s\n", ie_type);
					if (atoi(ie_type) <= 255)
					{
						fo->ies_status[ie_idx].type = atoi(ie_type);
						fo->ies_status[ie_idx++].enabled = onoff;
					}
				}
			}
		}
	}

	fclose(fp1);
	return 0;
}

int owfuzz_config_get_ext_ies_status(char *cfg_file, fuzzing_option *fo)
{
	FILE *fp1;
	char buf[256] = {0};
	char ie_type[64] = {0};
	int rc = 0, onoff;
	int ie_idx = 0;

	fp1 = owfuzz_config_open(cfg_file);
	if (fp1 == NULL)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "Failed to open '%s'.", NULL == cfg_file ? "owfuzz.cfg" : cfg_file);
		return -1;
	}

	while (!feof(fp1))
	{
		memset(buf, 0, sizeof(buf));
		if (fgets(buf, sizeof(buf), fp1))
		{
			if (buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n')
				continue;

			if (buf[0] == '[')
			{
				if (strstr(buf, "[ext-ies-status]") && (rc == 0))
				{
					rc = 1;
					continue;
				}
				else
				{
					if (rc == 1)
					{
						rc = 0;
						break;
					}
					else
						continue;
				}
			}

			if (rc)
			{
				onoff = 0;
				sscanf(buf, "%[^=]=%d", ie_type, &onoff);
				if (onoff == 1)
				{
					// printf("%s\n", ie_type);
					if (atoi(ie_type) <= 255)
					{
						fo->ext_ies_status[ie_idx].type = atoi(ie_type);
						fo->ext_ies_status[ie_idx++].enabled = onoff;
					}
				}
			}
		}
	}

	fclose(fp1);
	return 0;
}

/*
	Call the 'iw' and 'add' command
*/
int owfuzz_add_virtual_interface(char *iface, char *vif, char *type)
{
	char exec_cmd[256] = {0};

	sprintf(exec_cmd, "sudo iw %s interface add %s type %s", iface, vif, type);
	fuzz_logger_log(FUZZ_LOG_INFO, exec_cmd);

	return system(exec_cmd);
}

/*
	Call the 'iw' command and 'del'
*/
int owfuzz_del_virtual_interface(char *vif)
{
	char exec_cmd[256] = {0};

	sprintf(exec_cmd, "sudo iw dev %s del", vif);
	fuzz_logger_log(FUZZ_LOG_INFO, exec_cmd);

	return system(exec_cmd);
}

/*
	Call the 'macchanger' command
*/
int owfuzz_change_interface_mac(char *iface, char *mac)
{
	char exec_cmd[256] = {0};
	char szerr[256] = {0};
	int ret;

	kismet_interface_down(iface, szerr);
	sleep(1);

	sprintf(exec_cmd, "macchanger --mac=%s %s >/dev/null 2>&1", mac, iface);
	ret = system(exec_cmd);

	sleep(1);
	kismet_interface_up(iface, szerr);

	fuzz_logger_log(FUZZ_LOG_DEBUG, exec_cmd);

	return ret;
}
