import { Config } from "@remotion/cli/config";

Config.setVideoImageFormat("jpeg");
Config.setOverwriteOutput(true);
Config.setConcurrency(4);
Config.setBrowserExecutable("/usr/bin/chromium");
Config.setChromiumOpenGlRenderer("angle");

Config.setDelayRenderTimeoutInMilliseconds(120000);
