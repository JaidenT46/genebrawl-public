import {TeamManager} from "../../logic/home/team/TeamManager";
import {GameButton} from "../../titan/flash/gui/GameButton";
import {IButtonListener} from "../../titan/flash/gui/IButtonListener";
import {Stage} from "../../titan/flash/Stage";
import {ResourceManager} from "../../titan/ResourceManager";
import {Resources} from "../Resources";

export class OpenChatButton extends GameButton {
    constructor() {
        super();

        const chatMovieClip = ResourceManager.getMovieClip(Resources.UI, "gameroom_party_mode");
        const drawer = chatMovieClip.getChildByName("button_chat");
        const movieClip = drawer.getChildById(1);

        this.setMovieClip(movieClip);
        //this.setText("Chat"); 

        let v8 = Stage.getPointSize() != 0.0 ? Stage.getPointSize() : 0.1;
        let v11 = (Stage.getOffset340() - ((Stage.getSafeMarginBottom() + Stage.getSafeMarginTop()) / v8)) - 20;

        const v13 = this.getWidth();
        const v14 = (Stage.getOffset336() - (Stage.getSafeMarginRight() + Stage.getSafeMarginLeft()) / v8);

        this.setXY(v14 - v13, v11);
        this.visibility = false;

        this.setButtonListener(new IButtonListener(this.callback));
    }

    protected callback(listener: NativePointer, button: NativePointer) {
        console.log("OpenChatButton::callback called!");
        TeamManager.openTeamChat();
    }
}