import {GameSliderComponent} from "../../titan/flash/gui/GameSliderComponent";
import {ScrollArea} from "../../titan/flash/ScrollArea";
import {Configuration} from "../Configuration";
import {DebugMenuBase} from "../debug/DebugMenuBase";
import {DebugSliderComponent} from "../debug/DebugSliderComponent";
import {ToggleDebugClickerButton} from "../debug/ToggleDebugClickerButton";
import {LocalizationManager} from "../localization";

export class BattleSettingsPopup extends DebugMenuBase {
    private readonly toggleDebugClickerButton: ToggleDebugClickerButton;
    private sliderArray: DebugSliderComponent[] = [];
    private shouldUpdateScrollArea: boolean = false;

    constructor() { // TODO: ScrollArea
        super("preview_menu");

        this.setTitle(LocalizationManager.getString("BATTLE_SETTINGS"));

        this.toggleDebugClickerButton = new ToggleDebugClickerButton();
        this.toggleDebugClickerButton.setMovieClip(this.movieClip.getChildByName("close_button"));

        this.movieClip.getChildByName("preview_area").visibility = false;

        const title = this.movieClip.getChildByName("title");
        title.setXY(title.x + 20, title.y);

        this.createScrollArea();

        this.createSlider("BUTTONS_OPACITY", 0, 100, Configuration.opacity, function (slider: GameSliderComponent) {
            Configuration.opacity = slider.getCurrentValue();
        });

        this.createSlider("CAMERA_X", -10000, 10000, Configuration.cameraX, function (slider: GameSliderComponent) {
            Configuration.cameraX = slider.getCurrentValue();
        });

        this.createSlider("CAMERA_Y", -10000, 10000, Configuration.cameraY, function (slider: GameSliderComponent) {
            Configuration.cameraY = slider.getCurrentValue();
        });

        this.createSlider("CAMERA_ROTATE_X", -100000, 100000, Configuration.cameraRotateX, function (slider: GameSliderComponent) {
            Configuration.cameraRotateX = slider.getCurrentValue();
        });

        this.createSlider("CAMERA_ROTATE_Y", -100000, 100000, Configuration.cameraRotateY, function (slider: GameSliderComponent) {
            Configuration.cameraRotateY = slider.getCurrentValue();
        });

        this.createSlider("CAMERA_ALIGN", -100000, 100000, Configuration.cameraAlign, function (slider: GameSliderComponent) {
            Configuration.cameraAlign = slider.getCurrentValue();
        });

        this.createSlider("CAMERA_DISTANCE", -100000, 100000, Configuration.cameraDistance, function (slider: GameSliderComponent) {
            Configuration.cameraDistance = slider.getCurrentValue();
        });

        this.needToUpdateLayout();
    }

    needToUpdateLayout(): void {
        this.shouldUpdateScrollArea = true;
    }

    createScrollArea() {
        let itemArea = this.getMovieClip().getTextFieldByName("item_area");
        let itemWidth = itemArea!.getWidth();
        let itemHeight = itemArea!.getHeight();

        this.scrollArea = new ScrollArea(itemWidth, itemHeight + 75, 1);
        this.scrollArea.setUnk(true);

        let itemX = itemArea!.x;
        let itemY = itemArea!.y;

        this.scrollArea.setXY(itemX, itemY - 75);
        this.scrollArea.enablePinching(false);
        this.scrollArea.setAlignment(4);
        this.scrollArea.enableHorizontalDrag(false);

        this.movieClip.addChild(this.scrollArea);
    }

    createSlider(name: string, minValue: number, maxValue: number, currentValue: number, updateCallback: Function) {
        const localizedName = LocalizationManager.getString(name);
        const slider = new DebugSliderComponent(localizedName, 0, 120, updateCallback);

        const title = this.movieClip.getTextFieldByName("title")?.x!;

        const textField = slider.getBgMovieClip().getTextFieldByName("TID_EDIT_SCALE")!;

        textField.setXY(textField.x, textField.y - 5);

        slider.setXY(title / 2 - 20, 30 + slider.getHeight() * this.sliderArray.length);

        slider.setValueBounds(minValue, maxValue);
        slider.setCurrentValue(currentValue);

        //this.addChild(slider)

        this.sliderArray.push(slider);
    }

    update(deltaTime: number): void {
        //super.update(deltaTime)
        if (this.shouldUpdateScrollArea) {
            this.updateScrollLayout();
        }

        for (const slider of this.sliderArray) {
            this.updateSlider(slider);
        }
    }

    updateScrollLayout() {
        const self = this;

        this.scrollArea.removeAllContent();

        let Y = 0;

        this.sliderArray.forEach((slider, index) => {
            const textField = slider.getBgMovieClip().getTextFieldByName("TID_EDIT_SCALE")!;

            textField.setXY(textField.x, textField.y - 10);

            slider.setXY(slider.getWidth() / 2, Y); // this.sliderArray.length

            Y += slider.getHeight();

            self.scrollArea.addChild(slider);
        });

        this.shouldUpdateScrollArea = false;
    }

    updateSlider(slider: DebugSliderComponent) {
        slider.update();
    }
}