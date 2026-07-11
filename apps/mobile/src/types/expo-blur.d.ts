declare module "expo-blur" {
  import * as React from "react";
  import { ViewProps } from "react-native";
  export interface BlurViewProps extends ViewProps {
    intensity?: number;
    tint?: "light" | "dark" | "default";
  }
  export class BlurView extends React.Component<BlurViewProps> {}
}
