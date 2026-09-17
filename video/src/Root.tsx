import React from "react";
import { Composition } from "remotion";
import { AtharVideo, DURATION } from "./Video";

export const RemotionRoot: React.FC = () => {
  return (
    <Composition
      id="Athar"
      component={AtharVideo}
      durationInFrames={DURATION}
      fps={30}
      width={1920}
      height={1080}
    />
  );
};
