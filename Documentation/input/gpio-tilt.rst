Driver for tilt-switches connected via GPIOs
============================================

Generic driver to read data from tilt switches connected via gpios.
Orientation can be provided by one or more than one tilt switches,
i.e. each tilt switch providing one axis, and the number of axes
is also not limited.


Data structures:
----------------

The array of struct gpio in the gpios field is used to list the gpios
that represent the current tilt state.

The array of struct gpio_tilt_axis describes the axes that are reported
to the input system. The values set therein are used for the
input_set_abs_params calls needed to init the axes.

The array of struct gpio_tilt_state maps gpio states to the corresponding
values to report. The gpio state is represented as a bitfield where the
bit-index corresponds to the index of the gpio in the struct gpio array.
In the same manner the values stored in the axes array correspond to
the elements of the gpio_tilt_axis-array.


Example:
--------

Example configuration for a single TS1003 tilt switch that rotates around
one axis in 4 steps and emits the current tilt via two GPIOs::

    static int sg060_tilt_enable(struct device *dev) {
	    /* code to enable the sensors */
    };

    static void sg060_tilt_disable(struct device *dev) {
	    /* code to disable the sensors */
    };

    static struct gpio sg060_tilt_gpios[] = {
	    { SG060_TILT_GPIO_SENSOR1, GPIOF_IN, "tilt_sensor1" },
	    { SG060_TILT_GPIO_SENSOR2, GPIOF_IN, "tilt_sensor2" },
    };

    static struct gpio_tilt_state sg060_tilt_states[] = {
	    {
		    .gpios = (0 << 1) | (0 << 0),
		    .axes = (int[]) {
			    0,
		    },
	    }, {
		    .gpios = (0 << 1) | (1 << 0),
		    .axes = (int[]) {
			    1, /* 90 degrees */
		    },
	    }, {
		    .gpios = (1 << 1) | (1 << 0),
		    .axes = (int[]) {
			    2, /* 180 degrees */
		    },
	    }, {
		    .gpios = (1 << 1) | (0 << 0),
		    .axes = (int[]) {
			    3, /* 270 degrees */
		    },
	    },
    };

    static struct gpio_tilt_axis sg060_tilt_axes[] = {
	    {
		    .axis = ABS_RY,
		    .min = 0,
		    .max = 3,
		    .fuzz = 0,
		    .flat = 0,
	    },
    };

    static struct gpio_tilt_platform_data sg060_tilt_pdata= {
	    .gpios = sg060_tilt_gpios,
	    .nr_gpios = ARRAY_SIZE(sg060_tilt_gpios),

	    .axes = sg060_tilt_axes,
	    .nr_axes = ARRAY_SIZE(sg060_tilt_axes),

	    .states = sg060_tilt_states,
	    .nr_states = ARRAY_SIZE(sg060_tilt_states),

	    .debounce_interval = 100,

	    .poll_interval = 1000,
	    .enable = sg060_tilt_enable,
	    .disable = sg060_tilt_disable,
    };

    static struct platform_device sg060_device_tilt = {
	    .name = "gpio-tilt-polled",
	    .id = -1,
	    .dev = {
		    .platform_data = &sg060_tilt_pdata,
	    },
    };
