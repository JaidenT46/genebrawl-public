import {MovieClip} from "../../titan/flash/MovieClip";
import {HomeMode} from "./HomeMode";
import {Libg} from "../../libs/Libg";
import {LogicThemeData} from "../data/LogicThemeData";
import {GameMain} from "../../laser/client/GameMain";
import {ResourceManager} from "../../titan/ResourceManager";
import {SoundManager} from "../../titan/sound/SoundManager";
import {LogicDataTables} from "../data/LogicDataTables";
import {Configuration} from "../../gene/Configuration";
import {GlobalID} from "../data/GlobalID";
import {Stage} from "../../titan/flash/Stage";
import {LogicVersion} from "../LogicVersion";
import {MessageManager} from "../../laser/client/network/MessageManager";
import {TeamSetMemberReadyMessage} from "../message/team/TeamSetMemberReadyMessage";
import {Debug} from "../../gene/Debug";
import {SpeechCharacter} from "../../gene/popups/SpeechCharacter";
import {ContextMenu} from "../../titan/flash/gui/ContextMenu";
import {Libc} from "../../libs/Libc";
import {DownloadedImage} from "../../titan/flash/DownloadedImage";
import {UserImagesManager} from "../../gene/features/UserImagesManager";
import {EDebugCategory} from "../../gene/debug/DebugMenuCategory";
import {UsefulInfo} from "../../gene/features/UsefulInfo";

const themeDataOffset = 2208; // xref from HomeScreen_calculateThemeScale, below that call
const themeMovieClipOffset = 2096; // in HomeScreen_calculateThemeScale, smth like `v8 = sub_A4EBB4(*(_QWORD *)(a1 + 2096), "bg_colour");`

const HomeScreen_calculateThemeScale = new NativeFunction(
    Libg.offset(0x6E39E4, 0x278A38), 'void', ['pointer']
);

const HomeScreen_onRankedMatchTerminatedMessage = new NativeFunction(
    Libg.offset(0x6EC164, 0x27F090), 'void', ['pointer', 'pointer'] // 22159 or "TID_RANKED_MATCH_TERMINATED_REASON_%i"
);

/*
This is not HomeScreen::enter, this is just an inlined refreshTheme or whatever
HomeScreen::init calls this anyway, so why we need this useless offset?
чтобы ты спросил
привет

const HomeScreen_enter = new NativeFunction(
    Libg.offset(-1, -1, -1), 'void', [ 'pointer' ] // "HomeScreen::enter - active theme sc file doesn't exist! theme: "
)*/

const HomeScreen_init = Libg.offset(0x6E28CC, 0x277BE0);

export class HomeScreen {
    static speechCharacter?: SpeechCharacter;

    static getInstance() {
        return HomeMode.getHomeScreen();
    }

    static calculateThemeScale() { // should be called after setThemeMovieClip!
        HomeScreen_calculateThemeScale(this.getInstance());
    }

    static setThemeMovieClip(movieClip: MovieClip) {
        this.getInstance().add(themeMovieClipOffset).writePointer(movieClip.instance);
    }

    static setThemeImage(image: DownloadedImage) {
        this.getInstance().add(themeMovieClipOffset).writePointer(image.instance);
    }

    static getThemeMovieClip(): MovieClip {
        return new MovieClip(
            this.getInstance().add(themeMovieClipOffset).readPointer()
        );
    }

    static terminateRankedMatch() {
        HomeScreen_onRankedMatchTerminatedMessage(this.getInstance(), Libc.malloc(200));
    }

    static getThemeData(): LogicThemeData {
        return new LogicThemeData(
            this.getInstance().add(themeDataOffset).readPointer()
        );
    }

    static replaceThemeByMovieClip(theme: MovieClip) {
        let instance = this.getInstance();
        let homeSprite = GameMain.getHomeSprite();
        homeSprite.removeChild(instance.add(themeMovieClipOffset).readPointer());

        this.setThemeMovieClip(theme);
        this.calculateThemeScale();

        console.log(theme.x, theme.y, theme.getWidth(), theme.getHeight());
        //this.disableTheme(Configuration.darkTheme);
        //this.getThemeMovieClip().setXY(Stage.getX() + 75, theme.getY());

        homeSprite.addChildAt(instance.add(themeMovieClipOffset).readPointer(), 0);
    }

    static replaceThemeByImage(image: DownloadedImage) {
        const themeMovieClip = HomeScreen.getThemeMovieClip();

        const childAmounts = themeMovieClip.getChildAmount();

        for (let i = 0; i < childAmounts; i++) {
            const child = themeMovieClip.getChildById(i);

            child.visibility = false;
        }

        themeMovieClip.addChild(image);

        const stageX = Stage.getX();
        const stageY = Stage.getY();

        image.setScale(1); // because these motherfuckers set scale to big number (in test case, 343). ебанутые совсем?  

        image.setWidth(stageX * 2.2);
        image.setHeight(stageY * 2);
    }

    static replaceTheme(themeData: LogicThemeData, musicData: LogicThemeData, isForce: boolean = false) {
        let instance = this.getInstance();
        let homeSprite = GameMain.getHomeSprite();

        instance.add(themeDataOffset).writePointer(themeData.instance);

        homeSprite.removeChild(instance.add(themeMovieClipOffset).readPointer());

        console.log(themeData.getFileName());

        GameMain.loadAsset(themeData.getFileName());

        const themeMovieClip = ResourceManager.getMovieClip(themeData.getFileName(), themeData.getExportName());

        if (Configuration.useLegacyThemeMode) {
            this.setLegacyTheme(themeMovieClip, true);
        }

        this.setThemeMovieClip(themeMovieClip);
        this.calculateThemeScale();
        this.disableTheme(Configuration.darkTheme);

        homeSprite.addChildAt(instance.add(themeMovieClipOffset).readPointer(), 0);


        if (themeData.getGlobalID() == musicData.getGlobalID() || isForce) {
            console.log("theme set ok, changing music...");
            let music = musicData.getThemeMusic();
            if (music.isNull()) {
                music = LogicDataTables.getMenuMusic();
            }

            try {
                SoundManager.playMusic(music);
            } catch { }
        }
    }

    static setTheme(image: DownloadedImage) {
        let instance = this.getInstance();
        let homeSprite = GameMain.getHomeSprite();

        const oldTheme = this.getThemeMovieClip();

        const x = oldTheme.x;
        const y = oldTheme.y;
        const scale = oldTheme.getScale();

        image.setXY(x, y);

        homeSprite.removeChild(instance.add(themeMovieClipOffset).readPointer());

        this.setThemeImage(image);
        //this.calculateThemeScale();

        homeSprite.addChildAt(instance.add(themeMovieClipOffset).readPointer(), 0);

    }

    static setLegacyTheme(themeMovieClip: MovieClip, state: boolean = true) {
        try {
            const childAmount = themeMovieClip.getChildAmount();

            for (let i = 1; i < childAmount; i++) {
                const child = themeMovieClip.getChildById(i);

                if (child.getChildAmount() !== 1) {
                    child.visibility = !state;
                    continue;
                }

                const subChild = child.getChildById(0);

                try {
                    const nameOfChild = child.getNameOfChild(subChild);
                    if (nameOfChild !== "icon_skull") {
                        child.visibility = !state;
                    }
                } catch {
                    child.visibility = !state;
                }
            }
        } catch (e) {
            console.error(e);
        }
    }

    static disableTheme(state: boolean) {
        this.getThemeMovieClip().visibility = !state;
    }

    static patch() {
        /*Interceptor.attach(HomeScreen_enter, {
            onEnter(args) {
                if (Configuration.autoReady)
                    MessageManager.sendMessage(new TeamSetMemberReadyMessage(true));

                Debug.getOpenChatButton().visibility = false;
                ContextMenu.shouldShowContextMenu = true

                //setTimeout(APIManager.requestVouchers, 1500); // TODO: fix crash here
            },
            onLeave() {
                console.log("HomeScreen::enter called! configuration theme id: ", Configuration.themeId);

                if (Configuration.themeId !== -1) {
                    const themeData = LogicDataTables.getDataById(41, GlobalID.getInstanceID(Configuration.themeId)) as LogicThemeData;
    
                    HomeScreen.replaceTheme(themeData);
                }

                HomeScreen.disableTheme(Configuration.darkTheme);
            }
        })*/

        Interceptor.attach(HomeScreen_init, {
            onEnter(args) {
                if (Configuration.autoReady)
                    MessageManager.sendMessage(new TeamSetMemberReadyMessage(true));

                Debug.getOpenChatButton().visibility = false;
                ContextMenu.shouldShowContextMenu = true;

                UsefulInfo.ticks = 0;

                //setTimeout(APIManager.requestVouchers, 1500); // TODO: fix crash here
            },
            onLeave() {
                console.log("HomeScreen::enter called! configuration theme id:", Configuration.themeId);
                console.log("HomeScreen::enter called! configuration music theme id:", Configuration.themeMusicId);

                if (Configuration.themeId !== -1) {
                    const themeData = LogicDataTables.getDataById(41, GlobalID.getInstanceID(Configuration.themeId)) as LogicThemeData;
                    let musicData = themeData;
                    if (Configuration.themeMusicId !== -1) {
                        musicData = LogicDataTables.getDataById(41, GlobalID.getInstanceID(Configuration.themeMusicId)) as LogicThemeData;
                    }

                    if (themeData.isDisabled()) {
                        Configuration.themeId = -1;
                        Configuration.save();

                        return;
                    }

                    HomeScreen.replaceTheme(themeData, musicData, true);
                }

                const debugMenu = Debug.getDebugMenu();

                const category = debugMenu.getCategory(EDebugCategory.CHANGE_THEME)!;

                category.buttons.forEach(function (btn) {
                    if (!btn.getCheckbox().isNull())
                        btn.switchCheckbox(btn.instance.add(454).readInt() != HomeScreen.getThemeData().getInstanceId());
                });

                HomeScreen.disableTheme(Configuration.darkTheme);

                if (Configuration.currentUserThemeSet !== "") {
                    const image = UserImagesManager.getDownloadedImage(Configuration.currentUserThemeSet);

                    if (image) {
                        HomeScreen.replaceThemeByImage(image);
                    } else {
                        Configuration.currentUserThemeSet = "";
                        Configuration.save();
                    }
                }

                // Remove LogicVersion::isDeveloperBuild check if you need to test this.
                if (!Debug.available && !LogicVersion.isDeveloperBuild()) {
                    HomeScreen.speechCharacter = Debug.setupSpeechCharacter();
                }
            }
        });
    }
}
