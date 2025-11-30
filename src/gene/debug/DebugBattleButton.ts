import {GameButton} from "../../titan/flash/gui/GameButton";
import {IButtonListener} from "../../titan/flash/gui/IButtonListener";
import {ResourceManager} from "../../titan/ResourceManager";
import {Debug} from "../Debug";
import {Resources} from "../Resources";

export class DebugBattleButton extends GameButton {
    constructor(name: string, category: string, x: number) {
        super();

        this.setMovieClip(ResourceManager.getMovieClip(Resources.DEBUG, "debug_button"));
        this.setText(name);
        this.instance.add(490).writePointer(name.scptr());
        this.instance.add(498).writePointer(category.scptr());
        this.instance.add(516).writePointer(name.scptr());

        this.setXY(x, 150);

        this.setButtonListener(new IButtonListener(this.callback));
    }

    protected callback(listener: NativePointer, button: NativePointer) {
        Debug.getDebugMenu().buttonPressed(listener, button);
    }
}