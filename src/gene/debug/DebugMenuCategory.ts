import {GameStateManager} from "../../laser/client/state/GameStateManager";
import {GameButton} from "../../titan/flash/gui/GameButton";
import {IButtonListener} from "../../titan/flash/gui/IButtonListener";
import {ResourceManager} from "../../titan/ResourceManager";
import {Debug} from "../Debug";
import {Resources} from "../Resources";
import {DebugCommandButton} from "./DebugCommandButton";

export enum EDebugCategory {
    MAIN,
    ACCOUNT,
    BATTLE,
    LATENCY,
    CAMERA_MODE,
    BFP,
    CHANGE_THEME,
    FUN,
    GFX,
    PRC_CHINA,
    GAME_SETTINGS,
    OPTIMIZATION,
    PROXY,
    SC_UTILS,
    SERVERS,
    SKIN_CHANGER,
    TESTS,
    USEFUL_INFO,
    XRAY,
    MISC,
    PREVIEW,
    SC_ID,
    BRAWL_PASS,
    CHALLENGE,
    STREAMER_MODE,
    SPAM,
    GEARS,
    CHANGE_STATUS,
    EXPERIMENTAL
}

export class DebugMenuCategory extends GameButton {
    name: string;
    enumeration: EDebugCategory;
    mini: GameButton;
    buttons: GameButton[];

    constructor(name: string, enumeration: EDebugCategory) {
        super();

        this.setMovieClip(ResourceManager.getMovieClip(Resources.DEBUG, "debug_menu_category"));

        this.mini = new GameButton();
        this.mini.setMovieClip(ResourceManager.getMovieClip(Resources.DEBUG, "debug_menu_category_mini"));
        this.mini.setText(name.substring(0, 3));

        this.name = name;
        this.enumeration = enumeration;
        this.buttons = [];

        this.instance.add(449).writeU8(0);

        this.setButtonListener(new IButtonListener(this.buttonPressed));
        this.mini.setButtonListener(new IButtonListener(this.buttonPressed));
    }

    isCategoryOpened(): boolean {
        return Boolean(this.instance.add(449).readU8());
    }

    private buttonPressed(listener: NativePointer, button: NativePointer) {
        console.log("DebugMenuCategory::buttonPressed!");

        let dm = Debug.getDebugMenu();

        let gameButton = new GameButton(button);

        let y = gameButton.y;
        let height = gameButton.getHeight();

        dm.scrollArea.scrollTo(0.0, (y + - 5.0) + ((dm.scrollArea.instance.add(112).readFloat() - height) * 0.5), 1.0, 0.2);

        button.add(449).writeU8(Number(!button.add(449).readU8()));

        dm.needToUpdateLayout();
    }

    sortButtons(): GameButton[] {
        let buttons: GameButton[] = [];

        this.buttons.forEach(function (btn) {
            if (btn instanceof DebugCommandButton && !GameStateManager.isState(4)) {
                return;
            }

            buttons.push(btn);
        });

        return buttons;
    }
}