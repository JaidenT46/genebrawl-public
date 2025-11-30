import {GameButton} from "../../titan/flash/gui/GameButton";
import {GUI} from "../../titan/flash/gui/GUI";
import {IButtonListener} from "../../titan/flash/gui/IButtonListener";
import {Stage} from "../../titan/flash/Stage";
import {ResourceManager} from "../../titan/ResourceManager";
import {Configuration} from "../Configuration";
import {Resources} from "../Resources";

export class SVOButton extends GameButton {
    constructor() {
        super();

        this.setMovieClip(ResourceManager.getMovieClip(Resources.DEBUG, "debug_button"));
        this.setText("TEST");

        let v8 = Stage.getPointSize() != 0.0 ? Stage.getPointSize() : 0.1;
        let v11 = (Stage.getOffset340() - ((Stage.getSafeMarginBottom() + Stage.getSafeMarginTop()) / v8)) - 50;

        this.setXY(0, v11);
        this.visibility = Configuration.showSVOButton;

        this.setButtonListener(new IButtonListener(this.callback));
    }

    protected callback(listener: NativePointer, button: NativePointer) {
        console.log("SVOButton::callback");



        GUI.showFloaterText("bomb!");
    }
}