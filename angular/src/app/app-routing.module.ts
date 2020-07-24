import {NgModule} from '@angular/core';
import {Routes, RouterModule} from '@angular/router';
import {RoomComponent} from "./room/room.component";
import {InstrumentComponent} from "./instrument/instrument.component";
import {StudentComponent} from "./student/student.component";
import {TeacherComponent} from "./teacher/teacher.component";
import {CourseComponent} from "./course/course.component";
import {LessonComponent} from "./lesson/lesson.component";
import {LoginComponent} from "./login/login.component";

const routes: Routes = [
  {path: 'room', component: RoomComponent},
  {path: 'instrument', component: InstrumentComponent},
  {path: 'student', component: StudentComponent},
  {path: 'teacher', component: TeacherComponent},
  {path: 'course', component: CourseComponent},
  {path: 'lesson', component: LessonComponent},
  {path: 'login', component: LoginComponent},

  /* все непрописанные урл переправляются на login */
  {path: '**', redirectTo: '/login'}
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule {
}
