import {GameButton} from "../../titan/flash/gui/GameButton";
import {IButtonListener} from "../../titan/flash/gui/IButtonListener";
import {Stage} from "../../titan/flash/Stage";
import {ResourceManager} from "../../titan/ResourceManager";
import {Debug} from "../Debug";
import {Resources} from "../Resources";

export class DebugButton extends GameButton {
    constructor() {
        super();

        this.setMovieClip(ResourceManager.getMovieClip(Resources.DEBUG, "debug_button"));
        this.setText("D");

        let v8 = Stage.getPointSize() != 0.0 ? Stage.getPointSize() : 0.1;
        let v11 = (Stage.getOffset340() - ((Stage.getSafeMarginBottom() + Stage.getSafeMarginTop()) / v8));
        this.setXY(10, v11);
        this.setButtonListener(new IButtonListener(this.callback));
    }

    protected callback(listener: NativePointer, button: NativePointer) {
        console.log("click!");
        Debug.toggleDebugButtonPressed();
    }
}