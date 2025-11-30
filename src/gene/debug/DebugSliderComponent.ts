import {ResourceManager} from "../../titan/ResourceManager";
import {GameSliderComponent} from "../../titan/flash/gui/GameSliderComponent";
import {Resources} from "../Resources";

export class DebugSliderComponent extends GameSliderComponent {
    sliderName: string;
    private callback: Function;

    constructor(sliderName: string, x: number, y: number, updateCallback: Function) {
        const editControlsUi = ResourceManager.getMovieClip(Resources.UI, "edit_controls_ui");
        editControlsUi.setChildVisible("slider_opacity", false);

        const sliderScale = editControlsUi.getChildByName("slider_scale");
        sliderScale.setXY(x, y);

        const button = sliderScale.getChildByName("slider_button");

        super(sliderScale, button, 1);

        this.sliderName = sliderName;

        this.setValueBounds(0, 100);
        this.setXY(x, y);

        sliderScale.setText("TID_EDIT_SCALE", sliderName);

        this.callback = updateCallback;
    }

    override update() {
        super.update();

        this.callback(this);
    }
}