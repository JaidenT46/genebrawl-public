import {Libc} from "../../libs/Libc";
import {Libg} from "../../libs/Libg";
import {MovieClip} from "../../titan/flash/MovieClip";
import {MovieClipHelper} from "../../titan/flash/MovieClipHelper";
import {Rect} from "../../titan/flash/Rect";
import {ScrollArea} from "../../titan/flash/ScrollArea";
import {Stage} from "../../titan/flash/Stage";
import {TextField} from "../../titan/flash/TextField";
import {GUI} from "../../titan/flash/gui/GUI";
import {GameButton} from "../../titan/flash/gui/GameButton";
import {GameSliderComponent} from "../../titan/flash/gui/GameSliderComponent";
import {IButtonListener} from "../../titan/flash/gui/IButtonListener";
import {PopupBase} from "../../titan/flash/gui/PopupBase";
import {BlackListedPlayerButton} from "./buttons/BlackListedPlayerButton";

export class BlackListScreen extends PopupBase {
    private readonly textField: TextField;
    private clicksTextField!: TextField;
    private scrollArea: ScrollArea;
    private slider!: GameSliderComponent;

    constructor() {
        super(Libc.malloc(408), 'sc/ui.sc', "language_popup");

        this.instance.writePointer(Libg.offset(0x0, 0x0));
        this.instance.add(96).writePointer(Libg.offset(0x0, 0x0));
        this.instance.add(448).writeInt(0);

        this.setUpScreenHeader();

        this.scrollArea = new ScrollArea(0, 0, 1);
        this.instance.add(416).writePointer(this.scrollArea.instance);

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
        this.textField.setText("Black List");

        MovieClipHelper.autoAdjustText(this.textField);

        this.createScrollArea();
    }

    setActiveScrollArea(scrollArea: ScrollArea) {
        this.instance.add(416).writePointer(scrollArea.instance);
    }

    createScrollArea() {
        const rect = new Rect();
        const childMovieClip = new MovieClip(this.instance.add(112).readPointer());

        const area = childMovieClip.getTextFieldByName("area")!;
        GUI.resizeToScreenHeight(area);

        const safeMarginLeft = Stage.getSafeMarginLeft();
        const safeMarginRight = Stage.getSafeMarginRight();
        const pointSize = Stage.getPointSize() === 0.0 ? 0.1 : Stage.getPointSize();
        const offset336 = Stage.getOffset336();
        const areaHeight = area?.getHeight() as number;

        const v13 = ((offset336 - ((safeMarginRight + safeMarginLeft) / pointSize)) - areaHeight) * 0.5;
        const v14 = rect.instance.readFloat() - v13;
        const v15 = v13 + rect.instance.add(8).readFloat();

        rect.instance.writeFloat(v14);
        rect.instance.add(8).writeFloat(v15);

        const rectWidth = rect.getWidth();
        const rectHeight = rect.getHeight();

        const scrollArea = new ScrollArea(rectWidth, rectHeight, 1);

        this.setActiveScrollArea(scrollArea);

        scrollArea.setPixelSnappedXY(v14, 0.0);
        scrollArea.enablePinching(false);
        scrollArea.enableHorizontalDrag(false);
        scrollArea.enableVerticalDrag(true);
        scrollArea.setAlignment(4);
        scrollArea.setUnk(true);

        this.addContent(scrollArea);

        let naviHeight = this.getNaviHeight();

        let buttonIndex = 0;

        const testArray = ["#2PP"];

        for (const player of testArray) {
            const button = new BlackListedPlayerButton(player);

            button.setButtonListener(new IButtonListener(this.buttonClicked));

            const buttonWidth = button.getWidth();
            const buttonHeight = button.getHeight();

            const rectWidth = rect.getWidth();
            const buttonMiddleHeight = buttonHeight / 2;
            let buttonIndexTemp = buttonIndex;

            const x = (rectWidth / 2) + ((buttonIndexTemp + -1) * buttonWidth);
            const y = naviHeight + buttonMiddleHeight;

            button.setXY(x, y);

            if (buttonIndexTemp === 2) {
                naviHeight += buttonHeight;
            }

            buttonIndex = buttonIndexTemp - 2;

            if (buttonIndexTemp !== 2) {
                buttonIndex = buttonIndexTemp + 1;
            }

            scrollArea.addContent(button);
        }

        this.scrollArea = scrollArea;
    }

    buttonClicked(listener: NativePointer, button: NativePointer) {
        const gameButton = new GameButton(button);
        console.log("BlackListScreen.buttonClicked:", "pressed on", gameButton.getText());
    }

    setXy() {
        const x = Stage.getX();
        this.setPixelSnappedXY(x, 0.0);
    }

    update(deltaTime: number) {
        super.update(deltaTime);
    }
}