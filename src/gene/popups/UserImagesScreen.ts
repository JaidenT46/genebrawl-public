import {Libc} from "../../libs/Libc";
import {Libg} from "../../libs/Libg";
import {HomeScreen} from "../../logic/home/HomeScreen";
import {ResourceManager} from "../../titan/ResourceManager";
import {MovieClip} from "../../titan/flash/MovieClip";
import {MovieClipHelper} from "../../titan/flash/MovieClipHelper";
import {Rect} from "../../titan/flash/Rect";
import {ScrollArea} from "../../titan/flash/ScrollArea";
import {Stage} from "../../titan/flash/Stage";
import {TextField} from "../../titan/flash/TextField";
import {GUI} from "../../titan/flash/gui/GUI";
import {GameButton} from "../../titan/flash/gui/GameButton";
import {IButtonListener} from "../../titan/flash/gui/IButtonListener";
import {PopupBase} from "../../titan/flash/gui/PopupBase";
import {Configuration} from "../Configuration";
import {Debug} from "../Debug";
import {Resources} from "../Resources";
import {UserImagesManager} from "../features/UserImagesManager";
import {LocalizationManager} from "../localization";
import {DownloadImagePopup} from "./DownloadImagePopup";
import {OwnQuestionPopup} from "./OwnQuestionPopup";
import {ImageButton} from "./buttons/ImageButton";

export class UserImagesScreen extends PopupBase {
    private readonly textField: TextField;
    private loadImageButton!: GameButton;
    private scrollArea!: ScrollArea;
    private rect!: Rect;
    private buttons: GameButton[] = [];

    constructor() {
        super(Libc.malloc(456), 'sc/ui.sc', "language_popup"); // If crashes, find new malloc size. If still crashes, fuck supercell.

        this.instance.writePointer(Libg.offset(0x0, 0x0));
        this.instance.add(96).writePointer(Libg.offset(0x0, 0x0));
        this.instance.add(448).writeInt(0);

        this.setUpScreenHeader();

        this.scrollArea = new ScrollArea(0, 0, 1);
        this.instance.add(416).writePointer(this.scrollArea.instance);

        //this.scrollArea = new ScrollArea(0, 0, 1);
        //this.instance.add(416).writePointer(this.scrollArea.instance);

        this.movieClip = new MovieClip(
            this.instance.add(208).readPointer()
        );

        if (this.movieClip.instance.isNull()) {
            this.movieClip = new MovieClip(
                this.instance.add(112).readPointer()
            );
        }

        this.textField = this.movieClip.getTextFieldByName("title_txt")!;

        this.instance.add(432).writePointer(this.textField.instance);
        this.instance.add(440).writeFloat(this.textField.y);
        this.textField.setText(
            LocalizationManager.getString("USER_IMAGE_SCREEN_TITLE")
        );

        MovieClipHelper.autoAdjustText(this.textField);

        this.createScrollArea();
        this.populateScrollArea();
    }

    setActiveScrollArea(scrollArea: ScrollArea) {
        this.instance.add(416).writePointer(scrollArea.instance);
    }

    createScrollArea() {
        const rect = new Rect();
        const childMovieClip = new MovieClip(this.instance.add(112).readPointer());

        this.rect = rect;

        const area = childMovieClip.getTextFieldByName("area")!;
        GUI.resizeToScreenHeight(area);

        area.getBounds(childMovieClip, rect);

        const x = Stage.getX() * 2;
        const areaWidth = area.getWidth();

        const v10 = (x - areaWidth) * 0.5;
        const v11 = rect.instance.readFloat() - v10;
        const v12 = v10 + rect.instance.add(8).readFloat();

        rect.instance.writeFloat(v11);
        rect.instance.add(8).writeFloat(v12);

        const scrollArea = new ScrollArea(rect.getWidth(), rect.getHeight(), 1); // todo: if not working swap 1 and 3 args

        this.scrollArea = scrollArea;
        this.instance.add(416).writePointer(scrollArea.instance);
        this.scrollArea.instance.add(664).writeU8(1);

        scrollArea.setPixelSnappedXY(v11, 0.0);
        scrollArea.enablePinching(false);
        scrollArea.enableHorizontalDrag(false);
        scrollArea.enableVerticalDrag(true);
        scrollArea.setAlignment(4);
        scrollArea.setUnk(true);
        this.addContent(scrollArea);
    }

    populateScrollArea() {
        const buttonClip = ResourceManager.getMovieClip(Resources.UI, "language_item");

        const loadButton = new GameButton();
        loadButton.setMovieClip(buttonClip);
        loadButton.setText(
            LocalizationManager.getString("USER_IMAGE_BUTTON_LOAD_IMAGE")
        );
        loadButton.setXY(this.rect.getWidth() / 2, loadButton.getHeight());

        buttonClip.gotoAndStopFrameIndex(1);

        loadButton.setButtonListener(new IButtonListener(this.onLoadButtonClicked));

        this.scrollArea.addContentDontUpdateBounds(loadButton);

        this.loadImageButton = loadButton;

        let naviHeight = this.getNaviHeight();

        let buttonIndex = 0;
        const spacingX = 20;
        const spacingY = 0;

        const images = UserImagesManager.getImages();

        for (const image of images) {
            const button = new ImageButton(image);

            if (!image) continue;

            button.setButtonListener(new IButtonListener(this.buttonClicked));

            this.buttons.push(button);

            const buttonWidth = button.getWidth();
            const buttonHeight = button.getHeight();

            const rectWidth = this.rect.getWidth();

            const buttonMiddleHeight = buttonHeight / 2 + loadButton.getHeight();
            let buttonIndexTemp = buttonIndex;

            const x = (rectWidth / 2) + (buttonIndexTemp - 1) * (buttonWidth + spacingX);
            const y = naviHeight + buttonMiddleHeight + (spacingY * buttonHeight);

            button.setXY(x, y);

            if (buttonIndexTemp === 2) {
                naviHeight += buttonHeight;
            }

            buttonIndex = buttonIndexTemp - 2;

            if (buttonIndexTemp !== 2) {
                buttonIndex = buttonIndexTemp + 1;
            }

            this.scrollArea.addContentDontUpdateBounds(button);
        }

        this.scrollArea.updateBounds();
    }

    repopulateScrollArea() {
        this.scrollArea.removeAllContent();
        this.buttons = [];
        this.populateScrollArea();
    }

    onLoadButtonClicked(listener: NativePointer, button: NativePointer) {
        const downloadImagePopup = new DownloadImagePopup();

        GUI.showPopup(downloadImagePopup.instance, 1, 0, 1);
    }

    buttonClicked(listener: NativePointer, button: NativePointer) {
        const imageButton = new ImageButton(button);

        const o = new OwnQuestionPopup(
            LocalizationManager.getString("USER_IMAGE_SELECTED_TITLE"),
            LocalizationManager.getString("USER_IMAGE_SELECTED_BODY")
        );

        o.addPopupButton(
            "button_yes",
            LocalizationManager.getString("USER_IMAGE_SELECTED_BUTTON_SET_TO_THEME"),
            new IButtonListener((listener: NativePointer, button: NativePointer) => {
                const fileName = imageButton.getFileName();

                const image = UserImagesManager.getDownloadedImage(fileName);

                if (image) {
                    HomeScreen.replaceThemeByImage(image);

                    Configuration.currentUserThemeSet = fileName;
                    Configuration.save();

                    GUI.showFloaterText(
                        LocalizationManager.getString("USER_IMAGE_SET_TO_THEME_SUCCESS")
                    );
                }

                o.fadeOut();
            })
        );

        o.addPopupButton(
            "button_no",
            LocalizationManager.getString("USER_IMAGE_SELECTED_BUTTON_DELETE"),
            new IButtonListener((listener: NativePointer, gameButton: NativePointer) => {
                const fileName = imageButton.getFileName();

                const result = UserImagesManager.removeImage(fileName);

                if (result === 0) {
                    if (Configuration.currentUserThemeSet === fileName) {
                        Configuration.currentUserThemeSet = "";
                        Configuration.save();
                    }

                    if (Debug.getUserImagesScreen()) {
                        Debug.getUserImagesScreen().repopulateScrollArea();
                    }

                    GUI.showFloaterText(
                        LocalizationManager.getString("USER_IMAGE_DELETE_SUCCESS")
                    );
                } else {
                    GUI.showFloaterText(
                        LocalizationManager.getString("USER_IMAGE_DELETE_ERROR")
                    );
                }


                o.fadeOut();
            })
        );

        GUI.showPopup(o.instance, 1, 0, 1);
    }

    setXy() {
        const x = Stage.getX();
        this.setPixelSnappedXY(x, 0.0);
    }

    update(deltaTime: number) {
        super.update(deltaTime);
        //this.scrollArea.update(deltaTime)
    }
}