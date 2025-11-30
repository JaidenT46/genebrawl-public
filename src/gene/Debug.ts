import {GameMain} from "../laser/client/GameMain";
import {DebugButton} from "./debug/DebugButton";
import {DebugInfo} from "./debug/DebugInfo";
import {DebugMenu} from "./debug/DebugMenu";
import {DisplayObject} from "../titan/flash/DisplayObject";
import {DebugHud} from "./debug/DebugHud";
import {UsefulInfo} from "./features/UsefulInfo";
import {LogicVersion} from "../logic/LogicVersion";
import {Hamster} from "./features/Hamster";
import {LatencyManager} from "../laser/client/network/LatencyManager";
import {Configuration} from "./Configuration";
import {GUI} from "../titan/flash/gui/GUI";
import {SoundManager} from "../titan/sound/SoundManager";
import {LogicDataTables} from "../logic/data/LogicDataTables";
import {Application} from "../titan/utils/Application";
import {LocalizationManager} from "./localization/index";
import {Resources} from "./Resources";
import {GameStateManager} from "../laser/client/state/GameStateManager";
import {LobbyInfo} from "./features/LobbyInfo";
import {HamsterScreen} from "./popups/HamsterScreen";
import {SVOButton} from "./debug/SVOButton";
import {Storage} from "./Storage";
import {Constants} from "./Constants";
import {OpenChatButton} from "./debug/OpenChatButton";
import {BattleSettingsPopup} from "./popups/BattleSettingsPopup";
import {SpeechCharacter} from "./popups/SpeechCharacter";
import {HomeScreen} from "../logic/home/HomeScreen";
import {BattleDebug} from "./BattleDebug";
import {MessageManager} from "../laser/client/network/MessageManager";
import {UserImagesScreen} from "./popups/UserImagesScreen";
import {Filesystem} from "./features/filesystem";
import {Path} from "../titan/Path";

export class Debug {
    private static debugMenu?: DebugMenu;
    private static debugButton?: DebugButton;
    private static battleDebug?: BattleDebug;
    private static SVOButton?: SVOButton;
    private static openChatButton?: OpenChatButton;
    private static debugInfo?: DebugInfo;
    private static debugHud?: DebugHud;
    private static lobbyInfo?: LobbyInfo;
    private static hamsterScreen?: HamsterScreen;
    private static userImagesScreen?: UserImagesScreen;
    private static hamster?: Hamster;
    private static battleSettingsPopup?: BattleSettingsPopup;
    private static state: number;
    private static latencyTestsAdded: boolean;
    private static resourcesLoaded: boolean;

    private static enforceOpenNewHamsterMenu: boolean = true;
    static isGeneAssetsPreloaded: boolean = false;

    private static displayObjectQueue: DisplayObject[] = [];

    static init() {
        this.state = -1;
    }

    static addResourcesToLoad() {
        if (!this.resourcesLoaded) {
            try {
                Resources.loadList.map((asset: string) => {
                    try {
                        if (Filesystem.doesFileExist(Path.getUpdatePath() + asset)) {
                            GameMain.loadAsset(asset);
                        }
                        else {
                            if (Filesystem.doesFileExist(Path.getResourcePath() + asset)) {
                                GameMain.loadAsset(asset);
                            }
                            else {
                                console.warn("Debug.addResourcesToLoad:", "not exist:", asset);
                            }
                        }
                    } catch (e) {
                        console.warn("Debug.addResourcesToLoad:", "failed to load", asset);
                    }
                });
            } catch (e) {
                console.warn("Debug.addResourcesToLoad:", "failed to load resources!");
            }

            this.resourcesLoaded = true;
        }
    }

    static update(deltaTime: number) {
        if (this.debugMenu) {
            this.debugMenu.update(deltaTime);

            if (!this.latencyTestsAdded) {
                if (LatencyManager.latencyTestsDone() && MessageManager.getLatencyTests().length > 0) {
                    console.log("LatencyManager: tests are done, add servers to debug menu");

                    LatencyManager.addServersToDebugMenu(this.debugMenu);

                    this.latencyTestsAdded = true;
                }
            }
        }

        if (this.debugHud) {
            const usefulInfoState = UsefulInfo.canBeUpdated();

            if (usefulInfoState !== this.debugHud.getShowMessageState() && LogicVersion.isFree()) {
                this.debugHud.showMessages(usefulInfoState);
            }

            // fix useful info drawing same value and not updating  when its completely disabled
            UsefulInfo.update();

            this.debugHud.draw();
        }

        if (this.displayObjectQueue.length > 0) {
            let gameSprite = GameMain.getGameSprite();

            this.displayObjectQueue.forEach((child) => {
                gameSprite.addChild(child);
            });

            this.displayObjectQueue = [];
        }

        if (GameStateManager.isHomeMode()) {
            LatencyManager.update();
        }

        this.lobbyInfo?.update();
        this.battleSettingsPopup?.update(deltaTime);

        if (HomeScreen.speechCharacter) { // we need to hide this if mode was activated
            if (this.available) {
                HomeScreen.speechCharacter.hide();
                GameMain.getHomeSprite().removeChild(HomeScreen.speechCharacter);

                HomeScreen.speechCharacter = undefined;
            }
        }

        Storage.dvd.filter(e => e.createdOnStage).forEach(e => e.update());

        // TODO: don't forget to remove strip block when it's complete.
        /// #if DEBUG
        this.hamsterScreen?.update(deltaTime);

        if (this.hamster) {
            this.hamster.encountEnergyRestorationAmount();
        }

        // 11/30/2025 10:59 PM:
        // why is this part of the code under the DEBUG strip block?
        // wasn't this already a feature?
        if (this.openChatButton) {
            this.openChatButton.visibility = Configuration.showChatButton;
        }

        this.userImagesScreen?.update(deltaTime);
        /// #endif
    }

    static hideDebugItems() {
        this.debugButton?.hide();
        this.debugMenu?.hide();
        this.debugHud?.showMessages(false);
        this.debugInfo?.hide();

        Configuration.showDebugItems = false;
        Configuration.save();
    }

    static showDebugItems() {
        this.debugButton?.show();

        Configuration.showDebugItems = true;
        Configuration.save();
    }

    static createDebugInfo(): DebugInfo {
        Debug.debugInfo = new DebugInfo();

        return Debug.debugInfo;
    }

    static createSpeechCharacter(text: string): SpeechCharacter {
        return new SpeechCharacter(text);
    }

    static create() {
        try {
            this.destruct(); // To make sure old debug menu doesn't exist

            this.displayObjectQueue = [];

            this.spawnLobbyInfo();
            this.spawnDebugButton();
            this.spawnDebugBattle();
            //this.spawnSVOButton();
            this.spawnOpenChatButton();
            this.spawnDebugMenu();
            this.spawnDebugHud();
            this.spawnBattleSettings();

            //this.storeReloadData();

            console.log("Debug::create", "success!");
        } catch (e: any) {
            console.log(e.stack);
        }
    }

    private static spawnDebugBattle() {
        this.battleDebug = new BattleDebug();
        console.log("Debug.spawnDebugBattle");
    }

    private static spawnDebugButton() {
        this.debugButton = new DebugButton();

        this.displayObjectQueue.push(this.debugButton);

        console.log("Debug.spawnDebugButton:", "spawned debug button at " + this.debugButton.x + "," + this.debugButton.y);
    }

    private static spawnSVOButton() {
        this.SVOButton = new SVOButton();

        this.displayObjectQueue.push(this.SVOButton);
    }

    private static spawnOpenChatButton() {
        this.openChatButton = new OpenChatButton();

        this.displayObjectQueue.push(this.openChatButton);
    }

    private static spawnDebugMenu() {
        this.debugMenu = new DebugMenu();
        this.debugMenu.hide();

        this.displayObjectQueue.push(this.debugMenu);
    }

    private static spawnDebugHud() {
        this.debugHud = new DebugHud();
        this.debugHud.showMessages(true);
    }

    private static spawnBattleSettings() {
        this.battleSettingsPopup = new BattleSettingsPopup();
        this.battleSettingsPopup.hide();

        this.displayObjectQueue.push(this.battleSettingsPopup);
    }

    private static spawnUserImagesScreen() {
        this.userImagesScreen = new UserImagesScreen();
    }

    private static storeReloadData() {
        /// #if DEBUG
        if (LogicVersion.isDeveloperBuild()) {

            this.debugHud!.addMessage("Gene Brawl DEV Build");
        }
        /// #endif
    }

    private static spawnLobbyInfo() {
        this.lobbyInfo = new LobbyInfo();
        this.lobbyInfo.showInfo(true);

        GameMain.getHomeSprite().addChildAt(this.lobbyInfo, 0);
    }

    static toggleDebugButtonPressed() {
        /// #if DEBUG
        if (LogicVersion.isDeveloperBuild())
            this.state = 1; // bypass hack (if you want so, comment it, idc)
        /// #endif

        if (this.available || LogicVersion.isFree()) {
            if (this.debugInfo?.visibility) {
                this.debugInfo?.hide();
            }

            this.debugMenu?.toggle();
            console.log(this.debugMenu);
            if (this.hamster?.visibility) {
                this.hamster?.toggle();
            }

            if (this.battleSettingsPopup?.visibility) {
                this.battleSettingsPopup?.toggle();
            }

            Configuration.save(); // just to be sure
        }
        else {
            /// #if VIP
            if (Configuration.validKey === Constants.UNAVAILABLE_KEY_STRING) {
                return GUI.showFloaterText(
                    LocalizationManager.getString("KEY_UNAVAILABLE")
                );
            }

            GUI.showFloaterText(LocalizationManager.getString("NEED_TO_ACTIVATE").replace("$KEY", Configuration.validKey));
            Application.copyString(`/activate ${Configuration.validKey}`);
            /// #endif
        }
    }

    static setupSpeechCharacter() {
        const speechCharacter = this.createSpeechCharacter(LocalizationManager.getString("NEED_TO_ACTIVATE").replace("$KEY", Configuration.validKey));
        //if (shouldHide) speechCharacter?.hideAfter(3)
        GameMain.getHomeSprite().addChild(speechCharacter);

        return speechCharacter;
    }

    static toggleUserImagesButtonPressed() {
        this.userImagesScreen = new UserImagesScreen();

        this.userImagesScreen.setXy();

        GUI.showPopup(this.userImagesScreen.instance, 0, 0, 0);
    }

    static toggleDebugClickerButtonPressed() {
        if (!LogicVersion.isDeveloperBuild()) {
            const music = LogicDataTables.getMusicByName("Godzilla_Ingame"); // fuck this shit ass
            SoundManager.playMusic(music);
            return;
        }

        /// #if DEBUG
        if (this.enforceOpenNewHamsterMenu) {
            this.hamsterScreen = new HamsterScreen();

            this.hamsterScreen.setXy();

            GUI.showPopup(this.hamsterScreen.instance, 0, 0, 0);

            Debug.toggleDebugButtonPressed();
            return;
        }

        if (this.hamster) {
            this.hamster.toggle();
        }

        if (!this.hamster) {
            this.hamster = new Hamster();

            GameMain.getGameSprite().addChild(this.hamster);

        }
        /// #endif
    }

    static toggleSetAlphaButtonClicked() {
        this.battleSettingsPopup?.toggle();

        if (!this.battleSettingsPopup) {
            this.battleSettingsPopup = new BattleSettingsPopup();

            GameMain.getGameSprite().addChild(this.battleSettingsPopup);
        }
    }

    static getDebugButton(): DebugButton {
        return this.debugButton!;
    }

    static getBattleDebug(): BattleDebug {
        return this.battleDebug!;
    }

    static getSVOButton(): SVOButton {
        return this.SVOButton!;
    }

    static getOpenChatButton(): OpenChatButton {
        return this.openChatButton!;
    }

    static getDebugMenu(): DebugMenu {
        return this.debugMenu!;
    }

    static getHamster(): Hamster {
        return this.hamster!;
    }

    static getDebugHud(): DebugHud {
        return this.debugHud!;
    }

    static getHamsterScreen(): HamsterScreen {
        return this.hamsterScreen!;
    }

    static getLobbyInfo(): LobbyInfo {
        return this.lobbyInfo!;
    }

    static getAlphaPopup(): BattleSettingsPopup {
        return this.battleSettingsPopup!;
    }

    static getUserImagesScreen(): UserImagesScreen {
        return this.userImagesScreen!;
    }

    static destruct() {
        if (!this.debugButton) {
            return;
        }

        this.debugButton.hide();
        GameMain.getGameSprite().removeChild(this.debugButton);
        this.debugButton = undefined;

        if (this.debugMenu) {
            this.debugMenu.hide();
            GameMain.getGameSprite().removeChild(this.debugMenu);

            this.debugMenu.destruct();
            this.debugMenu = undefined;
        }

        if (this.debugHud) {
            this.debugHud.showMessages(false);
            this.debugHud.destruct();
            this.debugHud = undefined;
        }

        if (this.debugInfo) {
            this.debugInfo.hide();

            GameMain.getGameSprite().removeChild(this.debugInfo);

            this.debugInfo.destruct();
        }

        if (this.lobbyInfo) {
            this.lobbyInfo.hide();

            GameMain.getHomeSprite().removeChild(this.lobbyInfo);

            this.lobbyInfo = undefined;
        }

        if (this.battleSettingsPopup) {
            this.battleSettingsPopup.hide();

            GameMain.getGameSprite().removeChild(this.battleSettingsPopup);

            this.battleSettingsPopup.destruct();
        }
    }

    static changeDebugAvailable(state: number) {
        this.state = state;
    }

    static get available() {
        return this.state == 1;
    }

    static get isChecked() {
        return this.state != -1;
    }
}