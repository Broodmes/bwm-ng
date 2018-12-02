import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  //title = 'app';
  componentTitle = "some component text";

  clickHandler() {
    alert("I Am Clicked")
  }
}
