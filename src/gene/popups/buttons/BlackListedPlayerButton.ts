import {ResourceManager} from "../../../titan/ResourceManager";
import {GameButton} from "../../../titan/flash/gui/GameButton";
import {Resources} from "../../Resources";

export class BlackListedPlayerButton extends GameButton {
    text: string = "";
    constructor(text: string) {
        super();

        this.text = text;

        this.setMovieClip(ResourceManager.getMovieClip(Resources.UI, "language_item"));
        this.setText(text);
        this.getMovieClip().gotoAndStopFrameIndex(1);
    }

    setSelected(state: boolean) {
        this.getMovieClip().gotoAndStopFrameIndex(Number(!state));
    }
}