import {ResourceManager} from "../../titan/ResourceManager";
import {Resources} from "../Resources";
import {DebugMenuBase} from "./DebugMenuBase";
import {ToggleDebugMenuButton} from "./ToggleDebugMenuButton";

export class DebugInfo extends DebugMenuBase {
    private readonly toggleDebugMenuButton: ToggleDebugMenuButton;
    private lastLineY: number;

    constructor() {
        super("debug_menu");

        this.setTitle("Debug Info");

        this.toggleDebugMenuButton = new ToggleDebugMenuButton();
        this.toggleDebugMenuButton.setMovieClip(this.movieClip.getChildByName("close_button"));

        this.movieClip.addChild(this.toggleDebugMenuButton);

        this.lastLineY = 0.0;
    }

    addLine(line: string) {
        let debugMenuTxt = ResourceManager.getMovieClip(Resources.DEBUG, "debug_menu_text");
        let textField = debugMenuTxt.getTextFieldByName("Text");

        textField!.setText(line);
        textField!.setFontSize(17);

        debugMenuTxt.setXY(debugMenuTxt.x, this.lastLineY);

        this.scrollArea.addContent(debugMenuTxt);

        this.lastLineY += debugMenuTxt.getHeight() + 3.0;
    }
}