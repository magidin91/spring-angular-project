import { Injectable } from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {Observable} from "rxjs";
import {Page} from "../_model/page";
import {PageParams} from "../_model/page-params";

@Injectable({
  providedIn: 'root'
})
export class LessonService {

  constructor(private _httpClient: HttpClient) {}

  getLessonList(sort: string, order: string, page: number, pageSize: number): Observable<Page> {
    const href = '/api/lesson/list';

    return this._httpClient.post<Page>(href, new PageParams(page*pageSize, pageSize, {
      orderBy:sort,
      orderDir:order
    }));
  }
}
