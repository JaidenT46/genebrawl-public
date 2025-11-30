import {GameMain} from "../../laser/client/GameMain";
import {ResourceManager} from "../../titan/ResourceManager";
import {Screen} from "../../titan/device/Screen";
import {MovieClip} from "../../titan/flash/MovieClip";
import {TextField} from "../../titan/flash/TextField";
import {DebugHudMessageCollector} from "./DebugHudMessageCollector";
import {Libc} from "../../libs/Libc";
import {Resources} from "../Resources";

export class DebugHud {
    protected mainMovieClip: MovieClip;
    protected textField: TextField | null;
    protected movieClip: MovieClip;
    private showMessage: boolean = false;
    private messageCollector: DebugHudMessageCollector;

    constructor() {
        this.messageCollector = new DebugHudMessageCollector();
        this.mainMovieClip = ResourceManager.getMovieClip(Resources.DEBUG, "debug_menu_text");
        this.textField = this.mainMovieClip.getTextFieldByName("Text");

        if (this.textField === null) {
            console.error("DebugHud::DebugHud", "TextField is NULL!");
        }

        this.movieClip = new MovieClip(this.textField?.instance as NativePointer);
        this.movieClip.setXY(10, 10);
        GameMain.getGameSprite().addChild(this.movieClip); // так-как debughud не наследуется от DisplayObject
    }

    showMessages(state: boolean) {
        this.showMessage = state;
        this.mainMovieClip.setChildVisible("Text", state);
    }

    addMessage(line: string) {
        this.messageCollector.addMessage(line);

        const lastLineY = 30 * this.messageCollector.getMessageCount();
        const screenHeight = Screen.getHeight();

        if (lastLineY > screenHeight) {
            const overload = lastLineY - screenHeight;
            const amount = Math.ceil(overload / 30);

            this.messageCollector.setMessages(this.messageCollector.getMessages().slice(amount));
        }
    }

    setMessageCollector(messageCollector: DebugHudMessageCollector) {
        this.messageCollector = messageCollector;
    }

    draw() {
        if (this.showMessage) {
            this.textField?.setText(this.messageCollector.combineMessageLinesToString());
        }
    }

    getShowMessageState() {
        return this.showMessage;
    }

    destruct() {
        this.showMessage = false;

        GameMain.getGameSprite().removeChild(this.mainMovieClip);
        try {
            Libc.free(this.mainMovieClip.instance);
        }
        catch (e) { }

        GameMain.getGameSprite().removeChild(this.movieClip);
        try {
            Libc.free(this.movieClip.instance);
        }
        catch (e) { }
    }
}