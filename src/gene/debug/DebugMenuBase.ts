import {DropGUIContainer} from "../../titan/flash/gui/DropGUIContainer";
import {ScrollArea} from "../../titan/flash/ScrollArea";
import {Stage} from "../../titan/flash/Stage";
import {GameButton} from "../../titan/flash/gui/GameButton";
import {DebugCommandButton} from "./DebugCommandButton";
import {IButtonListener} from "../../titan/flash/gui/IButtonListener";
import {DebugMenuCategory, EDebugCategory} from "./DebugMenuCategory";
import {Resources} from "../Resources";
import {LocalizationManager} from "../localization";

export class DebugMenuBase extends DropGUIContainer {
    scrollArea: ScrollArea;
    protected tabScrollArea?: ScrollArea;
    protected shouldUpdateLayout: boolean;
    protected buttons: GameButton[];

    constructor(exportName: string) {
        super(Resources.DEBUG, exportName);

        this.buttons = [];

        let v8 = 0.1;

        let v9 = Stage.getSafeMarginLeft();
        let v10 = Stage.getSafeMarginRight();
        if (Stage.getPointSize() != 0.0) {
            v8 = Stage.getPointSize();
        }
        let v11 = (Stage.getOffset340() - ((Stage.getSafeMarginBottom() + Stage.getSafeMarginTop()) / v8));
        let v12 = Stage.getOffset336();
        let v13 = this.getHeight();

        this.setScale(v11 / v13);

        let v14 = (v12 - (v10 + v9) / v8);

        this.setPixelSnappedXY(v14, 0.0);


        let itemArea = this.getMovieClip().getTextFieldByName("item_area");
        let itemWidth = itemArea!.getWidth();
        let itemHeight = itemArea!.getHeight();

        this.scrollArea = new ScrollArea(itemWidth, itemHeight + - 5.0, 1);
        this.scrollArea.setUnk(true);

        let itemX = itemArea!.x;
        let itemY = itemArea!.y;

        this.scrollArea.setXY(itemX, itemY + 5.0);
        this.scrollArea.enablePinching(false);
        this.scrollArea.setAlignment(4);
        this.scrollArea.enableHorizontalDrag(false);

        this.movieClip.addChild(this.scrollArea);
        let tabArea = this.movieClip.getTextFieldByName("tab_area");
        if (tabArea) {
            this.tabScrollArea = new ScrollArea(tabArea!.getWidth(), tabArea!.getHeight(), 1);
            this.tabScrollArea.setUnk(true);

            this.tabScrollArea.setXY(tabArea!.x, tabArea!.y);
            this.tabScrollArea.enablePinching(false);
            this.tabScrollArea.setAlignment(8);
            this.tabScrollArea.enableHorizontalDrag(true);
            this.tabScrollArea.enableVerticalDrag(false);

            this.movieClip.addChild(this.tabScrollArea);
        }

        this.movieClip.setChildVisible("clear_button", false);
        this.movieClip.setChildVisible("debug_menu_input_button", true);

        this.createCategory(" ", EDebugCategory.MAIN);
        this.shouldUpdateLayout = false;
    }

    needToUpdateLayout() {
        this.shouldUpdateLayout = true;
    }

    buttonPressed(listener: NativePointer, button: NativePointer) {
        console.log("DebugMenuBase::buttonPressed: should be OVERRIDEN!");
    }

    createCategory(categoryName: string, enumeration: EDebugCategory): DebugMenuCategory {
        let category = new DebugMenuCategory(categoryName, enumeration);
        this.buttons.push(category);
        return category;
    }

    getCategory(enumeration: EDebugCategory): DebugMenuCategory | null {
        let category: DebugMenuCategory | null = null;

        this.buttons.forEach(function (btn) {
            if (btn instanceof DebugMenuCategory) {
                if ((btn as DebugMenuCategory).enumeration == enumeration) {
                    category = btn;
                    return;
                }
            }
        });

        return category;
    }

    removeCategory(enumeration: EDebugCategory) {
        this.buttons = this.buttons.filter((btn) => {
            if (btn instanceof DebugMenuCategory) {
                return btn.enumeration != enumeration;
            }
            return true;
        });

        this.needToUpdateLayout();
    }

    addButton(button: GameButton | DebugCommandButton, categoryEnum?: EDebugCategory) {
        if (!(button instanceof DebugCommandButton)) {
            button.setButtonListener(new IButtonListener(this.buttonPressed));
        }

        if (categoryEnum) {
            let category: DebugMenuCategory | null = this.getCategory(categoryEnum);
            if (!category) {
                const categoryTranslation = LocalizationManager.getString(
                    EDebugCategory[categoryEnum]
                );
                category = this.createCategory(categoryTranslation, categoryEnum);
            }

            category.buttons.push(button);
        }

        else
            this.buttons.push(button);
    }

    setTitle(title: string) {
        this.setText("title", title);
    }

    update(deltaTime: number): void {
        if (this.shouldUpdateLayout) {
            this.updateLayout();
        }

        this.scrollArea.update(deltaTime);
        this.tabScrollArea?.update(deltaTime);
    }

    private updateLayout() {
        const self = this;

        this.tabScrollArea?.removeAllContent();
        this.scrollArea.removeAllContent();

        if (this.tabScrollArea) {
            let i = 0;

            this.buttons.forEach(function (btn) {
                if (btn instanceof DebugMenuCategory) {
                    btn.mini.setXY(i * 45.0 + 20.0, 25);

                    self.tabScrollArea!.addContent(btn.mini);

                    i += 1;
                }
            });
        }

        let Y = 0.0;

        this.buttons.forEach(function (btn) {
            if (btn instanceof DebugMenuCategory) {
                let categoryButtons = btn.sortButtons();
                if (categoryButtons.length > 0) {
                    let width = btn.getWidth();
                    let height = btn.getHeight();

                    btn.setXY(width * 0.5, Y + (height * 0.5));

                    self.scrollArea.addContent(btn);

                    Y += 8.0 + height;

                    let prefix = btn.isCategoryOpened() ? "- " : "+ ";

                    btn.setText(prefix + btn.name);

                    if (btn.isCategoryOpened()) {
                        categoryButtons.forEach(function (a) {
                            let width = a.getWidth();
                            let height = a.getHeight();

                            a.setXY(width * 0.5, Y + (height * 0.5));

                            self.scrollArea.addContent(a);

                            Y += 8.0 + height;
                        });
                    }
                }
            }
            else {
                let width = btn.getWidth();
                let height = btn.getHeight();

                btn.setXY(width * 0.5, Y + (height * 0.5));

                self.scrollArea.addContent(btn);

                Y += 8.0 + height;
            }
        });

        this.shouldUpdateLayout = false;
    }

    destruct() {
        this.scrollArea.removeAllContent();
        this.tabScrollArea?.removeAllContent();
    }

    toggle() {
        this.visibility ? this.hide() : this.show();
    }
}