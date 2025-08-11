/*******************************************************************************
  Copyright (C), 2014, TP-LINK TECHNOLOGIES CO., LTD.
  File name   : mp2617-charger.c
  Description : Driver for charge ic mp2617.
  Author      : linyunfeng

  History:
------------------------------
V0.2, 2014-04-29, linyunfeng    complete the driver of mp2617.
V0.1, 2014-03-29, linyunfeng    create file.
*******************************************************************************/

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/power_supply.h>
#include <linux/slab.h>
#include <linux/of_gpio.h>
#include <linux/qpnp/qpnp-adc.h>

#ifdef MP2617_DEBUG
#undef dev_dbg
#define dev_dbg(dev, format, arg...)  dev_printk(KERN_INFO, dev, format, ##arg)
#endif

/* USB, set 500mA limit */
#define USB_INPUT_CURRENT_LIMIT_UA	500000

/* Charger, set 1000mA limit */
#define CHARGER_INPUT_CURRENT_LIMIT_UA	1000000

static u32 supported_input_current[] = {
	USB_INPUT_CURRENT_LIMIT_UA,
	CHARGER_INPUT_CURRENT_LIMIT_UA,
};

#define DEFAULT_INPUT_CURRENT_LIMIT_UA	CHARGER_INPUT_CURRENT_LIMIT_UA

/* Default resistor used for detection */
#define DEFAULT_CHARGE_DET_RESISTOR	100

/* Default battery resistor */
#define DEFAULT_BATTERY_RESISTOR	120

/* Correspondence table of voltage and temperature */
static const int adc_map_temp[][2] =
{
   {1800, -100},
   {1577, -20},
   {1524, -15},
   {1463, -10},
   {1396,  -5},
   {1322,   0},
   {1243,   5},
   {1159,  10},
   {1073,  15},
   {986,   20},
   {900,   25},
   {816,   30},
   {736,   35},
   {660,   40},
   {590,   45},
   {526,   50},
   {468,   55},
   {416,   60},
   {369,   65},
   {327,   70},
   {0,   1000}
};

struct mp2617_chip {
	struct platform_device	*client;
	struct power_supply	psy;
	struct power_supply	*usb_psy;
	struct mutex		lock;
	int			input_current_limit_ua;
#ifdef CONFIG_POWER_BANK_DETECT_SUPPORT
	int			charging_det_resistor;
	int			battery_resistor;
	u32			boost_en_gpio;
#endif
	int			battery_health;
	int			charging_vbat_div;
	bool			battery_present;
	bool			charging_enabled;
	bool			charging_allowed;
	u32			charging_en_gpio;
	u32			charging_ok_gpio;
	u32			charging_m0_gpio;
	u32			charging_m1_gpio;
};

static enum power_supply_property mp2617_power_properties[] = {
	POWER_SUPPLY_PROP_HEALTH,
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_TEMP,
	POWER_SUPPLY_PROP_CHARGING_ENABLED,
	POWER_SUPPLY_PROP_CURRENT_MAX,
	POWER_SUPPLY_PROP_TECHNOLOGY,
	POWER_SUPPLY_PROP_MODEL_NAME,
	POWER_SUPPLY_PROP_MANUFACTURER,
	POWER_SUPPLY_PROP_CHG_OK,
#ifdef CONFIG_POWER_BANK_DETECT_SUPPORT
	POWER_SUPPLY_PROP_VOLTAGE_DROP,
#endif
};

#ifdef CONFIG_POWER_BANK_DETECT_SUPPORT
/*******************************************************************************
  Function    : mp2617_enable_boost
  Description : Enable or disable the boost chip
  Input       : chip: chip data
                enable: true: enable, false: disable
  Output      : None
  Return      : 0: OK, Others: Error
  Others      : None
*******************************************************************************/
static int mp2617_enable_boost(struct mp2617_chip *chip, bool enable)
{
	int rc = 0;

	if (true == enable) {
		rc = gpio_direction_output(chip->boost_en_gpio, 1);
	} else {
		rc = gpio_direction_output(chip->boost_en_gpio, 0);
	}

	if (rc < 0) {
		dev_err(&chip->client->dev, "%s: enable or disable boost error\n",
			__func__);
	}

	dev_dbg(&chip->client->dev, "%s, enable=%d, rc = %d\n", __func__, enable, rc);

	return rc;
}

/*******************************************************************************
  Function    : mp2617_get_property_voltage_drop
  Description : Get the voltage drop by power supply
  Input       : chip: chip data
  Output      : None
  Return      : voltage or error code
  Others      : None
*******************************************************************************/
static int mp2617_get_property_voltage_drop(struct mp2617_chip *chip)
{
	int rc = 0;
	int vol_drop = 0;

	struct qpnp_vadc_result results;

	rc = qpnp_vadc_read(P_MUX1_1_1, &results);
	if (rc) {
		pr_err("Unable to read vbat rc=%d\n", rc);
		return rc;
	}

	vol_drop = ((int)(results.physical)/chip->charging_det_resistor)
			* chip->battery_resistor / 1000;
	return vol_drop;
}
#endif

/*******************************************************************************
  Function    : mp2617_enable_charging
  Description : Enable charging
  Input       : chip: chip data
  Output      : None
  Return      : 0: OK, Others: Error
  Others      : None
*******************************************************************************/
static int mp2617_enable_charging(struct mp2617_chip *chip)
{
	int rc = 0;

	if ((!chip->charging_enabled) && (true == chip->charging_allowed)
		&& (true == chip->battery_present)) {
		rc = gpio_direction_output(chip->charging_en_gpio, 1);

		if (!rc) {
			chip->charging_enabled = true;
#ifdef CONFIG_POWER_BANK_DETECT_SUPPORT
			mp2617_enable_boost(chip, false);
#endif
		}
	}

	dev_dbg(&chip->client->dev, "%s, rc = %d\n", __func__, rc);

	return rc;
}

/*******************************************************************************
  Function    : mp2617_disable_charging
  Description : Disable charging
  Input       : chip: chip data
  Output      : None
  Return      : 0: OK, Others: Error
  Others      : None
*******************************************************************************/
static int mp2617_disable_charging(struct mp2617_chip *chip)
{
	int rc = 0;

	if (chip->charging_enabled) {
		rc = gpio_direction_output(chip->charging_en_gpio, 0);

		if (!rc) {
			chip->charging_enabled = false;
#ifdef CONFIG_POWER_BANK_DETECT_SUPPORT
			mp2617_enable_boost(chip, true);
#endif
		}
	}

	dev_dbg(&chip->client->dev, "%s, rc = %d\n", __func__, rc);

	return rc;
}

/*******************************************************************************
  Function    : mp2617_get_property_chg_ok_level
  Description : Get the level of chg_ok gpio
  Input       : chip: chip data
  Output      : None
  Return      : Gpio level
  Others      : None
*******************************************************************************/
static int mp2617_get_property_chg_ok_level(struct mp2617_chip *chip)
{
	int rc = 0;
	int result = 0;

	rc = gpio_direction_input(chip->charging_ok_gpio);
	if (!rc) {
		result = gpio_get_value_cansleep(chip->charging_ok_gpio);
	}

	return result;
}

/*******************************************************************************
  Function    : mp2617_set_input_current_limit
  Description : Set the limit of input current
  Input       : chip: chip data
                current_limit_ua: the limit of input current
  Output      : None
  Return      : 0: OK, Others: Error
  Others      : None
*******************************************************************************/
static int mp2617_set_input_current_limit(struct mp2617_chip *chip,
					int current_limit_ua)
{
	int rc = 0;
	int i = 0;

	for (i = ARRAY_SIZE(supported_input_current) - 1; i >= 0; i--) {
		if (current_limit_ua >= supported_input_current[i]) {
			current_limit_ua = supported_input_current[i];
			break;
		}
	}

	switch (current_limit_ua) {
	case USB_INPUT_CURRENT_LIMIT_UA:
		gpio_direction_output(chip->charging_m0_gpio, 0);
		gpio_direction_output(chip->charging_m1_gpio, 0);
		break;

	case CHARGER_INPUT_CURRENT_LIMIT_UA:
		gpio_direction_output(chip->charging_m0_gpio, 1);
		gpio_direction_output(chip->charging_m1_gpio, 0);
		break;

	default:
		dev_err(&chip->client->dev, "%s: Unsupported current_limit_ua=%d uA\n",
			__func__, current_limit_ua);
		rc = -EINVAL;
		break;

	}

	if (!rc) {
		chip->input_current_limit_ua = current_limit_ua;

		dev_dbg(&chip->client->dev, "%s: current_limit_ua=%d uA\n", __func__,
			current_limit_ua);
	}

	return rc;
}

/*******************************************************************************
  Function    : mp2617_set_property_battery_present
  Description : Set the present state of battery
  Input       : chip: chip data
                batt_present_state: the present state of battery
  Output      : None
  Return      : 0: OK
  Others      : None
*******************************************************************************/
static int mp2617_set_property_battery_present(struct mp2617_chip *chip,
					bool batt_present_state)
{
	chip->battery_present = batt_present_state;

	return 0;
}

/*******************************************************************************
  Function    : mp2617_get_property_battery_present
  Description : Get the present state of battery
  Input       : chip: chip data
  Output      : None
  Return      : The present state of battery
  Others      : None
*******************************************************************************/
static int mp2617_get_property_battery_present(struct mp2617_chip *chip)
{
	return chip->battery_present;
}

/*******************************************************************************
  Function    : mp2617_set_property_battery_health
  Description : Set the health state of battery
  Input       : chip: chip data
                health_state: the health state of battery
  Output      : None
  Return      : 0: OK
  Others      : None
*******************************************************************************/
static int mp2617_set_property_battery_health(struct mp2617_chip *chip,
					int health_state)
{
	if ((health_state > POWER_SUPPLY_HEALTH_UNKNOWN) &&
		(health_state <= POWER_SUPPLY_HEALTH_DEAD_OVERCOLD))
	{
		chip->battery_health = health_state;

		if (POWER_SUPPLY_HEALTH_GOOD == health_state)
		{
			chip->charging_allowed = true;
		}
		else
		{
			chip->charging_allowed = false;
		}
	}
	else
	{
		chip->battery_health = POWER_SUPPLY_HEALTH_UNKNOWN;
	}

	return 0;
}

/*******************************************************************************
  Function    : mp2617_get_property_battery_health
  Description : Get the health state of battery
  Input       : chip: chip data
  Output      : None
  Return      : The health state of battery
  Others      : None
*******************************************************************************/
static int mp2617_get_property_battery_health(struct mp2617_chip *chip)
{
	return chip->battery_health;
}

/*******************************************************************************
  Function    : mp2617_get_property_battery_voltage
  Description : Get the voltage of battery
  Input       : chip: chip data
  Output      : None
  Return      : The voltage of battery
  Others      : None
*******************************************************************************/
static int mp2617_get_property_battery_voltage(struct mp2617_chip *chip)
{
	int rc = 0;
	struct qpnp_vadc_result results;

	rc = qpnp_vadc_read(P_MUX2_1_1, &results);
	if (rc) {
		pr_err("Unable to read vbat rc=%d\n", rc);
		return rc;
	}

	return ((int)(results.physical * chip->charging_vbat_div)/1000);
}

/*******************************************************************************
  Function    : em_batt_map_linear
  Description : Get the result form table by linear map
  Input       : table: linear map table
                table_size: table size
                in_num: number input
  Output      : out_num: result with linear map
  Return      : 0: OK, Others: Error
  Others      : None
*******************************************************************************/
static int em_batt_map_linear(const int (*table)[2], const u32 table_size,
	int in_num, int *out_num)
{
	u32 i = 0;

	if ((NULL == table) || (NULL == out_num)) {
		pr_err("Invalid input or output parameter\n");
		return -EINVAL;
	}

	while (i < table_size) {
		if (table[i][0] < in_num) {
			break;
		} else {
			i++;
		}
	}

	if (i == 0) {
		*out_num = table[0][1];
	} else if (i == table_size) {
		*out_num = table[table_size-1][1];
	} else {
		/* result is between search_index and search_index-1, interpolate linearly */
		*out_num = (((table[i][1] - table[i-1][1]) * (in_num - table[i-1][0]))
		/ (table[i][0] - table[i-1][0])) + table[i-1][1];
	}

	return 0;
}

/*******************************************************************************
  Function    : mp2617_get_property_battery_id_therm
  Description : Get the temperature of battery
  Input       : chip: chip data
  Output      : None
  Return      : The temperature of battery or error code
  Others      : None
*******************************************************************************/
static int mp2617_get_property_battery_id_therm(struct mp2617_chip *chip)
{
	int rc = 0;
	int temp_value = 0;
	struct qpnp_vadc_result results;

	rc = qpnp_vadc_read(LR_MUX2_BAT_ID, &results);
	if (rc) {
		pr_err("Unable to read battery temperature, rc=%d\n", rc);
		return rc;
	}

	temp_value = ((int)results.physical) / 1000; /* convert to mV */

	rc = em_batt_map_linear(adc_map_temp,
		sizeof(adc_map_temp)/sizeof(adc_map_temp[0]),
		temp_value, &temp_value);
	if(rc) {
		pr_err("Unable to get battery temperature, rc=%d\n", rc);
		return rc;
	}

	return temp_value;
}

static int mp2617_property_is_writeable(struct power_supply *psy,
						enum power_supply_property psp)
{
	switch (psp) {
	case POWER_SUPPLY_PROP_CHARGING_ENABLED:
	case POWER_SUPPLY_PROP_CURRENT_MAX:
	case POWER_SUPPLY_PROP_HEALTH:
	case POWER_SUPPLY_PROP_PRESENT:
		return 1;
	default:
		break;
	}

	return 0;
}

static int mp2617_power_set_property(struct power_supply *psy,
				  enum power_supply_property psp,
				  const union power_supply_propval *val)
{
	struct mp2617_chip *chip = container_of(psy, struct mp2617_chip, psy);

	mutex_lock(&chip->lock);

	switch (psp) {
	case POWER_SUPPLY_PROP_CHARGING_ENABLED:
		if (val->intval) {
			mp2617_enable_charging(chip);
		} else {
			mp2617_disable_charging(chip);
		}
		break;
	case POWER_SUPPLY_PROP_CURRENT_MAX:
		mp2617_set_input_current_limit(chip, val->intval);
		break;
	case POWER_SUPPLY_PROP_HEALTH:
		mp2617_set_property_battery_health(chip, val->intval);
		break;
	case POWER_SUPPLY_PROP_PRESENT:
		mp2617_set_property_battery_present(chip, (bool)val->intval);
		break;
	default:
		mutex_unlock(&chip->lock);
		return -EINVAL;
	}

	mutex_unlock(&chip->lock);

	power_supply_changed(&chip->psy);
	return 0;
}

static int mp2617_power_get_property(struct power_supply *psy,
				       enum power_supply_property psp,
				       union power_supply_propval *val)
{
	struct mp2617_chip *chip = container_of(psy, struct mp2617_chip, psy);

	mutex_lock(&chip->lock);

	switch (psp) {
	case POWER_SUPPLY_PROP_HEALTH:
		val->intval = mp2617_get_property_battery_health(chip);
		break;
	case POWER_SUPPLY_PROP_PRESENT:
		val->intval = mp2617_get_property_battery_present(chip);
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		val->intval = mp2617_get_property_battery_voltage(chip);
		break;
	case POWER_SUPPLY_PROP_TEMP:
		val->intval = mp2617_get_property_battery_id_therm(chip);
		break;
	case POWER_SUPPLY_PROP_CHG_OK:
		val->intval = mp2617_get_property_chg_ok_level(chip);
		break;
	case POWER_SUPPLY_PROP_CHARGING_ENABLED:
		val->intval = chip->charging_enabled;
		break;
	case POWER_SUPPLY_PROP_CURRENT_MAX:
		val->intval = chip->input_current_limit_ua;
		break;
	case POWER_SUPPLY_PROP_TECHNOLOGY:
		val->intval = POWER_SUPPLY_TECHNOLOGY_LION;
		break;
	case POWER_SUPPLY_PROP_MODEL_NAME:
		val->strval = "MP2617";
		break;
	case POWER_SUPPLY_PROP_MANUFACTURER:
		val->strval = "MPS";
		break;
#ifdef CONFIG_POWER_BANK_DETECT_SUPPORT
	case POWER_SUPPLY_PROP_VOLTAGE_DROP:
		val->intval = mp2617_get_property_voltage_drop(chip);
		break;
#endif
	default:
		mutex_unlock(&chip->lock);
		return -EINVAL;
	}

	mutex_unlock(&chip->lock);

	return 0;
}

/*******************************************************************************
  Function    : mp2617_external_power_changed
  Description : Set charging parameters because power supply device changes
  Input       : psy: power supply psy
  Output      : None
  Return      : None
  Others      : None
*******************************************************************************/
static void mp2617_external_power_changed(struct power_supply *psy)
{
	struct mp2617_chip *chip = container_of(psy, struct mp2617_chip, psy);
	union power_supply_propval prop = {0,};
	int scope = POWER_SUPPLY_SCOPE_DEVICE;
	int current_limit = 0;
	int online = 0;
	int rc;

	mutex_lock(&chip->lock);
	dev_dbg(&chip->client->dev, "%s: start\n", __func__);

	rc = chip->usb_psy->get_property(chip->usb_psy,
					POWER_SUPPLY_PROP_ONLINE, &prop);
	if (rc) {
		dev_err(&chip->client->dev,
			"%s: could not read USB online property, rc=%d\n", __func__, rc);
	} else {
		online = prop.intval;
	}

	rc = chip->usb_psy->get_property(chip->usb_psy, POWER_SUPPLY_PROP_SCOPE,
					&prop);
	if (rc) {
		dev_err(&chip->client->dev,
			"%s: could not read USB scope property, rc=%d\n", __func__, rc);
	} else {
		scope = prop.intval;
	}

	rc = chip->usb_psy->get_property(chip->usb_psy,
					POWER_SUPPLY_PROP_CURRENT_MAX, &prop);
	if (rc) {
		dev_err(&chip->client->dev,
			"%s: could not read USB current max property, rc=%d\n", __func__, rc);
	} else {
		current_limit = prop.intval;
	}

	dev_dbg(&chip->client->dev,
		"%s: online=%d, scope=%d, current_limit=%d, present=%d\n",
		__func__, online, scope, current_limit, chip->battery_present);

	if (scope == POWER_SUPPLY_SCOPE_DEVICE) {
		if (online && chip->battery_present) {
			mp2617_set_input_current_limit(chip, current_limit);

			if (current_limit != 0 &&
				POWER_SUPPLY_HEALTH_GOOD == chip->battery_health) {
				mp2617_enable_charging(chip);
			}
		} else {
			mp2617_disable_charging(chip);
		}
	}

	dev_dbg(&chip->client->dev, "%s: end\n", __func__);
	mutex_unlock(&chip->lock);

	power_supply_changed(&chip->psy);
}

/*******************************************************************************
  Function    : mp2617_apply_dt_configs
  Description : Set default config
  Input       : chip: chip data
  Output      : None
  Return      : 0: OK, Others: Error
  Others      : None
*******************************************************************************/
static int __devinit mp2617_apply_dt_configs(struct mp2617_chip *chip)
{
	struct device *dev = &chip->client->dev;
	struct device_node *node = chip->client->dev.of_node;
	int current_ma = 0;
	int value = 0;
	int rc = 0;

	chip->input_current_limit_ua = DEFAULT_INPUT_CURRENT_LIMIT_UA;
#ifdef CONFIG_POWER_BANK_DETECT_SUPPORT
	chip->charging_det_resistor = DEFAULT_CHARGE_DET_RESISTOR;
	chip->battery_resistor = DEFAULT_BATTERY_RESISTOR;
	mp2617_enable_boost(chip, true);
#endif
	chip->battery_health = POWER_SUPPLY_HEALTH_GOOD;
	chip->battery_present = true;
	chip->charging_allowed = true;

	mp2617_disable_charging(chip);

	/*
	 * All device tree parameters are optional so it is ok if read calls
	 * fail.
	 */
	rc = of_property_read_u32(node, "mps,chg-current-ma", &current_ma);
	if (rc == 0) {
		chip->input_current_limit_ua = current_ma * 1000;
	} else {
		dev_err(dev, "%s: Failed to get charge current node, rc=%d\n",
			__func__, rc);
	}

	rc = of_property_read_u32(node, "mps,chg-vbat-div", &value);
	if (rc == 0) {
		chip->charging_vbat_div = value;
	} else {
		chip->charging_vbat_div = 1;

		dev_err(dev, "%s: Failed to get battery voltage division, rc=%d\n",
			__func__, rc);
	}

	rc = mp2617_set_input_current_limit(chip, chip->input_current_limit_ua);
	if (rc) {
		dev_err(dev, "%s: Failed to set charge current, rc=%d\n",
			__func__, rc);
		return rc;
	}

#ifdef CONFIG_POWER_BANK_DETECT_SUPPORT
	rc = of_property_read_u32(node, "mps,chg-det-resistor", &value);
	if (rc == 0) {
		chip->charging_det_resistor = value;
	} else {
		dev_err(dev, "%s: Failed to get detection resistor, rc=%d\n",
			__func__, rc);
	}

	rc = of_property_read_u32(node, "mps,chg-batt-resistor", &value);
	if (rc == 0) {
		chip->battery_resistor = value;
	} else {
		dev_err(dev, "%s: Failed to get battery resistor, rc=%d\n",
			__func__, rc);
	}

#endif
	return rc;
}

/*******************************************************************************
  Function    : mp2617_gpio_configs
  Description : Set gpio default config
  Input       : chip: chip data
  Output      : None
  Return      : 0: OK, Others: Error
  Others      : None
*******************************************************************************/
static int __devinit mp2617_gpio_configs(struct mp2617_chip *chip)
{
	struct device_node *node = chip->client->dev.of_node;
	int rc = 0;

	chip->charging_en_gpio = of_get_named_gpio(node, "mps,chg-en-gpio", 0);
	rc = gpio_request(chip->charging_en_gpio, "mps,chg-en-gpio");
	if (rc) {
		pr_err("request charge en gpio failed, rc=%d\n", rc);
		gpio_free(chip->charging_en_gpio);
		return rc;
	}

	chip->charging_ok_gpio = of_get_named_gpio(node, "mps,chg-ok-gpio", 0);
	rc = gpio_request(chip->charging_ok_gpio, "mps,chg-ok-gpio");
	if (rc) {
		pr_err("request charge ok gpio failed, rc=%d\n",rc);
		gpio_free(chip->charging_ok_gpio);
		return rc;
	}

	chip->charging_m0_gpio = of_get_named_gpio(node, "mps,chg-m0-gpio", 0);
	rc = gpio_request(chip->charging_m0_gpio, "mps,chg-m0-gpio");
	if (rc) {
		pr_err("request charge m0 gpio failed, rc=%d\n",
			rc);
		gpio_free(chip->charging_m0_gpio);
		return rc;
	}

	chip->charging_m1_gpio = of_get_named_gpio(node, "mps,chg-m1-gpio", 0);
	rc = gpio_request(chip->charging_m1_gpio, "mps,chg-m1-gpio");
	if (rc) {
		pr_err("request charge m1 gpio failed, rc=%d\n",
			rc);
		gpio_free(chip->charging_m1_gpio);
		return rc;
	}

#ifdef CONFIG_POWER_BANK_DETECT_SUPPORT
	chip->boost_en_gpio = of_get_named_gpio(node, "mps,chg-boost-en-gpio", 0);
	rc = gpio_request(chip->boost_en_gpio, "mps,chg-boost-en-gpio");
	if (rc) {
		pr_err("request charge m1 gpio failed, rc=%d\n",
			rc);
		gpio_free(chip->boost_en_gpio);
		return rc;
	}
#endif

	return rc;
}

static int __devinit mp2617_probe(struct platform_device *pdev)
{
	struct mp2617_chip *chip;
	struct device *dev = &pdev->dev;
	struct device_node *node = pdev->dev.of_node;
	int rc = 0;

	if (!node) {
		dev_err(dev, "%s: device tree information missing\n", __func__);
		return -ENODEV;
	}

	chip = devm_kzalloc(dev, sizeof(*chip), GFP_KERNEL);
	if (!chip) {
		dev_err(dev, "%s: devm_kzalloc failed\n", __func__);
		return -ENOMEM;
	}

	mutex_init(&chip->lock);
	chip->client = pdev;

	chip->usb_psy = power_supply_get_by_name("usb");
	if (!chip->usb_psy) {
		dev_dbg(dev, "%s: USB supply not found; deferring charger probe\n",
			__func__);
		return -EPROBE_DEFER;
	}

	rc = mp2617_gpio_configs(chip);
	if (rc) {
		return rc;
	}

	rc = mp2617_apply_dt_configs(chip);
	if (rc) {
		return rc;
	}

	chip->psy.name			 = "battery";
	chip->psy.type			 = POWER_SUPPLY_TYPE_BATTERY;
	chip->psy.properties		 = mp2617_power_properties;
	chip->psy.num_properties	 = ARRAY_SIZE(mp2617_power_properties);
	chip->psy.get_property		 = mp2617_power_get_property;
	chip->psy.set_property		 = mp2617_power_set_property;
	chip->psy.property_is_writeable  = mp2617_property_is_writeable;
	chip->psy.external_power_changed = mp2617_external_power_changed;

	rc = power_supply_register(dev, &chip->psy);
	if (rc < 0) {
		dev_err(dev, "%s: power_supply_register failed, rc=%d\n",
						__func__, rc);
		return rc;
	}

	mp2617_external_power_changed(&chip->psy);

	dev_info(dev, "%s: MP2617 charger probed successfully\n", __func__);

	return rc;
}

static int __devexit mp2617_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id mp2617_match[] = {
	{ .compatible = "mps,mp2617", },
	{ },
};

static struct platform_driver mp2617_driver = {
	.driver	= {
		.name		= "mp2617",
		.owner		= THIS_MODULE,
		.of_match_table	= mp2617_match,
	},
	.probe		= mp2617_probe,
	.remove		= __devexit_p(mp2617_remove),
};

static int __init mp2617_init(void)
{
	return platform_driver_register(&mp2617_driver);
}
module_init(mp2617_init);

static void __exit mp2617_exit(void)
{
	return platform_driver_unregister(&mp2617_driver);
}
module_exit(mp2617_exit);

MODULE_DESCRIPTION("MP2617 Charger");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("mp2617");
