import {Libc} from "../../libs/Libc";
import {Libg} from "../../libs/Libg";
import {ResourceManager} from "../../titan/ResourceManager";
import {MovieClip} from "../../titan/flash/MovieClip";
import {MovieClipHelper} from "../../titan/flash/MovieClipHelper";
import {ScrollArea} from "../../titan/flash/ScrollArea";
import {Stage} from "../../titan/flash/Stage";
import {TextField} from "../../titan/flash/TextField";
import {GUI} from "../../titan/flash/gui/GUI";
import {GameButton} from "../../titan/flash/gui/GameButton";
import {IButtonListener} from "../../titan/flash/gui/IButtonListener";
import {PopupBase} from "../../titan/flash/gui/PopupBase";
import {Debug} from "../Debug";
import {Resources} from "../Resources";

export class HamsterScreen extends PopupBase {
    private readonly textField: TextField;
    private hamsterButton!: GameButton;
    private levelUpButton!: GameButton;
    clicks: number = 0;
    upgrade: number = 1;
    upgradeCost: number = 100;
    private clicksTextField!: TextField;
    private scrollArea: ScrollArea;

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
        this.textField.setText("Выберите количество тян");

        MovieClipHelper.autoAdjustText(this.textField);

        this.setUpTests();
        this.setUpHamster();
        this.setUpClicksText();
        this.setUpButtons();
    }

    setUpTests() {

    }

    setUpHamster() {
        const emojiMovieClip = ResourceManager.getMovieClip(Resources.EMOJI, "emoji_digger");

        emojiMovieClip.setXY(0, Stage.getY());
        emojiMovieClip.setScale(4);
        emojiMovieClip.playOnce();
        emojiMovieClip.setFrame(2);

        this.hamsterButton = new GameButton();

        this.hamsterButton.setMovieClip(emojiMovieClip);
        this.hamsterButton.setButtonListener(new IButtonListener(this.hamsterPressed));

        this.hamsterButton.visibility = false;

        this.addChild(this.hamsterButton);
    }

    closeButtonPressed() {
        const hamsterScreen = Debug.getHamsterScreen();

        hamsterScreen.fadeOut();
    }

    setUpClicksText() {
        const movieClip = ResourceManager.getMovieClip('sc/ui.sc', "language_popup");

        this.clicksTextField = movieClip.getTextFieldByName("title_txt")!;

        this.clicksTextField.setXY(this.clicksTextField.x, this.clicksTextField.y + this.textField.getHeight() + 10);
        this.clicksTextField.setFontSize(72);
        this.clicksTextField.setText("Clicks: " + this.clicks);

        MovieClipHelper.autoAdjustText(this.clicksTextField);

        this.clicksTextField.visibility = false;

        this.addChild(this.clicksTextField);
    }

    setUpButtons() {
        const button = ResourceManager.getMovieClip("sc/ui.sc", "popover_button_blue");

        button.setXY(Stage.getX() - button.getWidth(), Stage.getY());

        this.levelUpButton = new GameButton();

        this.levelUpButton.setMovieClip(button);

        this.levelUpButton.setText("Level UP! Cost: " + this.upgrade * this.upgradeCost);

        this.levelUpButton.setButtonListener(new IButtonListener(this.levelUpButtonPressed));

        this.levelUpButton.visibility = false;

        this.addChild(this.levelUpButton);
    }

    levelUpButtonPressed() {
        const hamster = Debug.getHamsterScreen();
        const cost = hamster.upgrade * hamster.upgradeCost;

        if (hamster.clicks < cost) {
            return GUI.showFloaterText("not enough");
        }

        hamster.clicks -= cost;
        hamster.upgrade++;
        GUI.showFloaterText("you're good");

        hamster.updateClicksText();
        hamster.updateLevelUpButton();
    }

    hamsterPressed() {
        const hamster = Debug.getHamsterScreen();

        hamster.clicks += 1 * hamster.upgrade;

        hamster.updateClicksText();
    }

    updateClicksText() {
        this.clicksTextField.setText("Clicks: " + this.clicks);
        MovieClipHelper.autoAdjustText(this.clicksTextField);
    }

    updateLevelUpButton() {
        this.levelUpButton.setText("Level UP! Cost: " + this.upgrade * this.upgradeCost);
    }

    setXy() {
        const x = Stage.getX();
        this.setPixelSnappedXY(x, 0.0);
    }

    update(deltaTime: number) {
        super.update(deltaTime);
    }
}